"""The five-agent demo: every scenario, Custody off vs on (in-process, deterministic)."""

import asyncio
import os
import socket

import pytest

from agent_applications.custody_demo.run import run
from agent_applications.custody_demo.scenarios import SCENARIOS


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    return {
        (r.scenario, r.custody): r
        for r in asyncio.run(run([], [False, True], "inproc", tmp_path_factory.mktemp("logs")))
    }


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_scenario_outcomes(results, scenario) -> None:
    off, on = results[(scenario.id, False)], results[(scenario.id, True)]
    assert off.verdict == scenario.expect["none"], off.reply
    assert on.verdict == scenario.expect["custody"], on.reply
    if scenario.kind == "attack":
        assert on.blocked


def test_custody_tokens_never_reach_replies(results) -> None:
    for r in results.values():
        assert "custody_" not in r.reply and "consent_" not in r.reply


def _ports_free() -> bool:
    for port in [*range(8101, 8107), *range(47100, 47106)]:
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return False
    return True


@pytest.mark.skipif(os.environ.get("CUSTODY_HTTP_TESTS") != "1",
                    reason="set CUSTODY_HTTP_TESTS=1 (starts 10 processes on fixed ports)")
def test_http_mode_matches_inproc(results, tmp_path) -> None:
    assert _ports_free()
    http = asyncio.run(run([], [False, True], "http", tmp_path))
    for r in http:
        assert r.goal_met == results[(r.scenario, r.custody)].goal_met, r.scenario
