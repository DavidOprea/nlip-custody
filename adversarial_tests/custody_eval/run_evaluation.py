"""Replay the attack and benign sets through the Custody demo app and score them.

    python -m adversarial_tests.custody_eval.run_evaluation
    python -m adversarial_tests.custody_eval.run_evaluation --mode http
    python -m adversarial_tests.custody_eval.run_evaluation --only ATK-01 BEN-20 -v

Every case runs through the real NLIP application (``agent_applications/
custody_demo``): the framework's server/client pipelines, the custody SE loaded from
``config.toml``, and the tool guard. Nothing calls the extension's internals.

Defences (columns): ``none`` (no SE), ``judge_heuristic`` and ``judge_llm`` (a content
judge at every door), ``per_hop`` (taint without propagation, Rule of Two),
``authority`` (Warrant-style caps) and ``custody``. See ``security_extensions/
baselines``. Only ``none`` and ``custody`` have per-case predictions; baselines are
measured, not predicted.

Outputs (in ``--out``, default ``results/``): ``results.json`` (one row per case and
defence) and ``summary.md``. The exit code is 1 if any case's verdict differs
from the verdict its ``expect`` field predicts.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
import tempfile
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from agent_applications.custody_demo.run import Result, run_scenarios
from agent_applications.custody_demo.scenarios import Scenario
from agent_applications.custody_demo.settings import DEFENSES

HERE = Path(__file__).resolve().parent
# Default order of columns. judge_llm calls the Anthropic API, so it runs only on request.
DEFAULT_DEFENSES = ["none", "judge_heuristic", "per_hop", "authority", "custody"]


def load(path: Path) -> list[Scenario]:
    cases = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                cases.append(Scenario.from_case(json.loads(line)))
            except (KeyError, ValueError) as error:
                raise SystemExit(f"{path.name}:{number}: {error}") from error
    return cases


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100 * k / n:.1f}% [{100 * lo:.1f}, {100 * hi:.1f}]" if n else "-"


def metrics(results: list[Result]) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = {}
    for defense in dict.fromkeys(r.defense for r in results):
        group = [r for r in results if r.defense == defense]
        if not group:
            continue
        attacks = [r for r in group if r.kind == "attack"]
        benign = [r for r in group if r.kind == "benign"]
        out[defense] = {
            "attacks": len(attacks),
            "attack_success": sum(r.goal_met for r in attacks),
            "benign": len(benign),
            "benign_done": sum(r.goal_met for r in benign),
            "benign_done_without_consent": sum(r.verdict == "done" for r in benign),
            "benign_needed_consent": sum(r.verdict == "consent" for r in benign),
            "benign_blocked": sum(r.verdict == "blocked" for r in benign),
            "benign_failed": sum(r.verdict == "failed" for r in benign),
            "mean_seconds_per_case": round(sum(r.seconds for r in group) / len(group), 4),
            "unexpected": [r.scenario for r in group if not r.as_expected],
        }
    return out


def summary(results: list[Result], scenarios: dict[str, Scenario], mode: str) -> str:
    m = metrics(results)
    lines = [f"# Custody evaluation (scripted worst case, {mode} mode)", "",
             "Rates are k/n with a 95% Wilson interval.", "",
             "| Metric | " + " | ".join(m) + " |", "| --- |" + " --- |" * len(m)]
    rows = [
        ("Attack success rate", lambda d: rate(d["attack_success"], d["attacks"])),
        ("Benign tasks completed", lambda d: rate(d["benign_done"], d["benign"])),
        ("Benign, no consent needed", lambda d: rate(d["benign_done_without_consent"], d["benign"])),
        ("Benign, needed consent", lambda d: rate(d["benign_needed_consent"], d["benign"])),
        ("Benign, blocked (false positive)", lambda d: rate(d["benign_blocked"], d["benign"])),
        ("Mean wall time per case (s)", lambda d: str(d["mean_seconds_per_case"])),
    ]
    for label, fn in rows:
        lines.append(f"| {label} | " + " | ".join(fn(d) for d in m.values()) + " |")

    lines += ["", "## Attack success by category", "",
              "| Category | Cases | " + " | ".join(m) + " |", "| --- | --- |" + " --- |" * len(m)]
    cats: dict[str, dict[str, list[Result]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        cats[r.category][r.defense].append(r)
    for kind, header in (("attack", None), ("benign", "## Benign outcomes by category")):
        if header:
            lines += ["", header, "", "| Category | Cases | " + " | ".join(m) + " |",
                      "| --- | --- |" + " --- |" * len(m)]
        for category, per in cats.items():
            rows_ = per[next(iter(m))]
            if not rows_ or rows_[0].kind != kind:
                continue
            cells = []
            for defense in m:
                rs = per[defense]
                if kind == "attack":
                    cells.append(f"{sum(r.goal_met for r in rs)}/{len(rs)} succeeded")
                else:
                    counts = defaultdict(int)
                    for r in rs:
                        counts[r.verdict] += 1
                    cells.append(", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
            lines.append(f"| {category} | {len(rows_)} | " + " | ".join(cells) + " |")

    unexpected = [r for r in results if not r.as_expected]
    lines += ["", "## Cases that differ from their prediction", ""]
    lines += [f"- `{r.scenario}` under `{r.defense}`: expected {r.expected}, got {r.verdict}"
              for r in unexpected] or ["None."]
    residual = [s for s in scenarios.values() if s.kind == "attack" and s.expect.get("custody") == "succeeds"]
    known_fp = [s for s in scenarios.values() if s.kind == "benign" and s.expect.get("custody") == "blocked"]
    lines += ["", "## Documented residual risks and known false positives", ""]
    lines += [f"- `{s.id}` (attack, succeeds under custody): {s.title}" for s in residual]
    lines += [f"- `{s.id}` (benign, blocked under custody): {s.title}" for s in known_fp]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attacks", default=str(HERE / "attacks.jsonl"))
    parser.add_argument("--benign", default=str(HERE / "benign.jsonl"))
    parser.add_argument("--defense", nargs="+", choices=[*DEFENSES, "all"], default=["all"],
                        help="defences to compare (default: all except judge_llm, which "
                             "calls the Anthropic API and needs credentials)")
    parser.add_argument("--mode", choices=["inproc", "http"], default="inproc")
    parser.add_argument("--only", nargs="*", help="run only these case ids")
    parser.add_argument("--out", default=str(HERE / "results"))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    scenarios = load(Path(args.attacks)) + load(Path(args.benign))
    if args.only:
        scenarios = [s for s in scenarios if s.id in set(args.only)]
    defenses = DEFAULT_DEFENSES if args.defense == ["all"] else args.defense
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    logs = Path(tempfile.mkdtemp(prefix="custody_eval_logs_"))

    results = asyncio.run(run_scenarios(scenarios, defenses, args.mode, logs))

    by_id = {s.id: s for s in scenarios}
    (out / "results.json").write_text(json.dumps(
        {"mode": args.mode, "metrics": metrics(results),
         "cases": [{**asdict(r), "verdict": r.verdict, "as_expected": r.as_expected} for r in results]},
        indent=2))
    text = summary(results, by_id, args.mode)
    (out / "summary.md").write_text(text, encoding="utf-8")
    print(text)
    if args.verbose:
        for r in results:
            print(f"--- {r.scenario} [{r.defense}] {r.verdict}\n{r.reply}")
    print(f"results: {out}  decision logs: {logs}")
    return 0 if all(r.as_expected for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
