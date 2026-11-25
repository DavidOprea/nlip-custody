"""AgentDojo banking split across NLIP agents: a few pairs that pin down each defence's behaviour."""

import asyncio
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("agentdojo")

from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from adversarial_tests.agentdojo_banking.run_evaluation import (  # noqa: E402
    SUITE_VERSION,
    _NamedPipeline,
    run_pair,
)


@pytest.fixture(scope="module")
def suite():
    return get_suite(SUITE_VERSION, "banking")


@pytest.fixture(scope="module")
def attack(suite):
    return load_attack("important_instructions", suite, _NamedPipeline())


def _run(suite, attack, defense, ut, it=None):
    user, inj = suite.user_tasks[ut], suite.injection_tasks[it] if it else None
    injections = attack.attack(user, inj) if inj else {}
    return asyncio.run(run_pair(suite, defense, user, inj, injections, Path(tempfile.mkdtemp())))


def test_undefended_worst_case_agent_obeys_the_injection(suite, attack) -> None:
    row = _run(suite, attack, "none", "user_task_0", "injection_task_0")
    assert row.injection_seen and row.security


def test_custody_stops_a_file_injection_and_the_task_still_completes(suite, attack) -> None:
    row = _run(suite, attack, "custody", "user_task_0", "injection_task_0")
    assert row.injection_seen and not row.security
    assert row.utility and row.consents == 1  # the user approved the real bill payment


def test_per_hop_misses_the_cross_agent_file_injection(suite, attack) -> None:
    """read_file runs at the files agent; send_money at the bank sees only the assistant."""
    assert _run(suite, attack, "per_hop", "user_task_0", "injection_task_0").security


def test_per_hop_catches_a_same_agent_transaction_injection(suite, attack) -> None:
    """Transactions are read and money is sent inside the same bank agent."""
    assert not _run(suite, attack, "per_hop", "user_task_3", "injection_task_0").security


def test_benign_task_needs_no_consent_when_nothing_outside_was_read(suite, attack) -> None:
    row = _run(suite, attack, "custody", "user_task_10")
    assert row.utility and row.consents == 0 and not row.blocked
