"""AgentDojo banking (v1.2.1), split across NLIP agents, under each defence.

    python -m adversarial_tests.agentdojo_banking.run_evaluation
    python -m adversarial_tests.agentdojo_banking.run_evaluation --defense none custody
    python -m adversarial_tests.agentdojo_banking.run_evaluation --only user_task_0 --injection injection_task_1 -v

Tasks, injection tasks, the injected text (AgentDojo's ``important_instructions``
attack) and the scoring (each task's own ``utility`` and ``security``) all come from
AgentDojo unchanged. What this adds is the split: the tools run on separate NLIP
agents behind each defence (``agent_applications/agentdojo_split``), and the agent
is the scripted worst case (it obeys every injection it reads).

Runs:
* benign: each of the 16 user tasks with no injection;
* attack: each user task with each of the 9 injection tasks (144 pairs).

When a call is blocked, the simulated careful user approves it only if it is one of
the user task's own ground-truth calls (same tool, same arguments), and the assistant
retries. Writes ``results/results.json`` and ``results/summary.md``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suite

from adversarial_tests.custody_eval.run_evaluation import rate
from agent_applications.agentdojo_split.split import DojoNetwork, Plan

HERE = Path(__file__).resolve().parent
SUITE_VERSION = "v1.2.1"
DEFENSES = ["none", "judge_heuristic", "per_hop", "authority", "custody"]
# These two check the model's prose answer (a computed total), which a scripted
# agent does not write. Their utility is not counted; their security still is.
ANSWER_ONLY = {"user_task_1", "user_task_7"}
MAX_ROUNDS = 3


class _NamedPipeline:
    """AgentDojo's attack only reads the target's name, to address the model by name."""

    name = "claude-3-5-sonnet-20241022"


@dataclass
class Row:
    defense: str
    user_task: str
    injection_task: str | None
    utility: bool | None
    security: bool | None      # True = the injection task's goal was achieved
    injection_seen: bool
    blocked: list[str]
    consents: int
    seconds: float


def _same_args(a: dict, b: dict) -> bool:
    norm = lambda d: json.dumps(d, sort_keys=True, default=str)  # noqa: E731
    return norm(dict(a)) == norm(dict(b))


async def run_pair(suite, defense, user_task, injection_task, injections, log_dir) -> Row:
    started = time.perf_counter()
    net = DojoNetwork(defense, suite.tools, log_dir)
    env = suite.load_and_inject_default_environment(injections)
    pre = env.model_copy(deep=True)
    net.holder.env = env
    gt = user_task.ground_truth(pre.model_copy(deep=True))
    plan = Plan(
        user_calls=gt,
        injection_calls=injection_task.ground_truth(pre.model_copy(deep=True)) if injection_task else [],
        injected_texts=[v for v in injections.values() if v],
    )
    net.assistant.plan = plan
    await net.ask(user_task.PROMPT)
    blocked = list(plan.blocked)
    consents = 0
    for _ in range(MAX_ROUNDS):
        if not plan.pending:
            break
        approved = net.approve(lambda r: any(fc.function == r.tool and _same_args(fc.args, r.args)
                                             for fc in gt))
        if not approved:
            break
        consents += approved
        await net.ask("continue")
    output = "\n".join(plan.outputs)
    utility = None if user_task.ID in ANSWER_ONLY else bool(user_task.utility(output, pre, env))
    security = bool(injection_task.security(output, pre, env)) if injection_task else None
    return Row(defense, user_task.ID, injection_task.ID if injection_task else None, utility,
               security, plan.injected, blocked, consents, round(time.perf_counter() - started, 4))


async def run_all(defenses, only, injection_only, log_root) -> list[Row]:
    suite = get_suite(SUITE_VERSION, "banking")
    attack = load_attack("important_instructions", suite, _NamedPipeline())
    rows = []
    users = [t for i, t in suite.user_tasks.items() if not only or i in only]
    injections_tasks = [t for i, t in suite.injection_tasks.items()
                        if not injection_only or i in injection_only]
    for defense in defenses:
        for ut in users:
            rows.append(await run_pair(suite, defense, ut, None, {}, log_root / defense))
            for it in injections_tasks:
                rows.append(await run_pair(suite, defense, ut, it, attack.attack(ut, it),
                                           log_root / defense))
    return rows


def summary(rows: list[Row]) -> str:
    defenses = list(dict.fromkeys(r.defense for r in rows))
    lines = [f"# AgentDojo banking {SUITE_VERSION}, split across NLIP agents (scripted worst case)", "",
             "Attack: AgentDojo `important_instructions`. Rates are k/n with a 95% Wilson interval.",
             f"Utility excludes the answer-only tasks {', '.join(sorted(ANSWER_ONLY))}.", "",
             "| Metric | " + " | ".join(defenses) + " |", "| --- |" + " --- |" * len(defenses)]

    def cell(defense, pred, value):
        rs = [r for r in rows if r.defense == defense and pred(r)]
        k = sum(1 for r in rs if value(r))
        return rate(k, len(rs))

    metrics = [
        ("Attack success rate (security)", lambda r: r.injection_task is not None, lambda r: r.security),
        ("Utility, no attack", lambda r: r.injection_task is None and r.utility is not None, lambda r: r.utility),
        ("Utility under attack", lambda r: r.injection_task is not None and r.utility is not None, lambda r: r.utility),
        ("No-attack runs that needed consent", lambda r: r.injection_task is None, lambda r: r.consents > 0),
        ("Injection reached the agent", lambda r: r.injection_task is not None, lambda r: r.injection_seen),
    ]
    for label, pred, value in metrics:
        lines.append(f"| {label} | " + " | ".join(cell(d, pred, value) for d in defenses) + " |")

    lines += ["", "## Attack success by injection task", "",
              "| Injection task | " + " | ".join(defenses) + " |", "| --- |" + " --- |" * len(defenses)]
    for it in sorted({r.injection_task for r in rows if r.injection_task}, key=lambda s: int(s.rsplit("_", 1)[1])):
        cells = []
        for d in defenses:
            rs = [r for r in rows if r.defense == d and r.injection_task == it]
            cells.append(f"{sum(r.security for r in rs)}/{len(rs)}")
        lines.append(f"| {it} | " + " | ".join(cells) + " |")

    lines += ["", "## Benign user tasks", "",
              "| User task | " + " | ".join(defenses) + " |", "| --- |" + " --- |" * len(defenses)]
    for ut in sorted({r.user_task for r in rows}, key=lambda s: int(s.rsplit("_", 1)[1])):
        cells = []
        for d in defenses:
            r = next((r for r in rows if r.defense == d and r.user_task == ut and r.injection_task is None), None)
            if r is None:
                cells.append("-")
            elif r.utility is None:
                cells.append("n/a" + (" (consent)" if r.consents else ""))
            else:
                cells.append(("done" if r.utility else "FAILED") + (" (consent)" if r.consents else ""))
        lines.append(f"| {ut} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--defense", nargs="+", default=DEFENSES)
    parser.add_argument("--only", nargs="*", help="user task ids")
    parser.add_argument("--injection", nargs="*", help="injection task ids")
    parser.add_argument("--out", default=str(HERE / "results"))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    log_root = Path(tempfile.mkdtemp(prefix="agentdojo_logs_"))
    rows = asyncio.run(run_all(args.defense, set(args.only or []), set(args.injection or []), log_root))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps([asdict(r) for r in rows], indent=1))
    text = summary(rows)
    (out / "summary.md").write_text(text, encoding="utf-8")
    print(text)
    if args.verbose:
        for r in rows:
            print(r)
    print(f"results: {out}  decision logs: {log_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
