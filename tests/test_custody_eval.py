"""The evaluation sets: well-formed, reproducible, and every case matches its prediction."""

import asyncio
import json

import pytest

from adversarial_tests.custody_eval import build_cases
from adversarial_tests.custody_eval.run_evaluation import HERE, load, metrics, wilson
from agent_applications.custody_demo.run import run_scenarios


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_jsonl_files_match_the_generator() -> None:
    assert _lines(HERE / "attacks.jsonl") == build_cases.build_attacks()
    assert _lines(HERE / "benign.jsonl") == build_cases.build_benign()


def test_sets_are_well_formed_and_benign_is_at_least_as_large() -> None:
    attacks, benign = load(HERE / "attacks.jsonl"), load(HERE / "benign.jsonl")
    ids = [s.id for s in attacks + benign]
    assert len(ids) == len(set(ids))
    assert all(s.kind == "attack" for s in attacks) and all(s.kind == "benign" for s in benign)
    assert len(benign) >= len(attacks) >= 30
    from agent_applications.custody_demo.settings import DEFENSES
    assert all({"none", "custody"} <= set(s.expect) <= set(DEFENSES) for s in attacks + benign)


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    scenarios = load(HERE / "attacks.jsonl") + load(HERE / "benign.jsonl")
    return asyncio.run(run_scenarios(scenarios, [False, True], "inproc",
                                     tmp_path_factory.mktemp("logs")))


def test_every_case_matches_its_prediction(results) -> None:
    wrong = [f"{r.scenario}/{r.defense}: expected {r.expected}, got {r.verdict}"
             for r in results if not r.as_expected]
    assert not wrong, wrong


def test_headline_numbers(results) -> None:
    m = metrics(results)
    assert m["none"]["attack_success"] == m["none"]["attacks"]  # every attack is real
    assert m["custody"]["attack_success"] == 2                   # the documented residuals
    assert m["custody"]["benign_blocked"] == 1                   # the documented false positive


def test_wilson_interval() -> None:
    lo, hi = wilson(0, 30)
    assert lo == 0.0 and 0.10 < hi < 0.12
    assert wilson(0, 0) == (0.0, 0.0)
