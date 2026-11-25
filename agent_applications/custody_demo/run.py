"""Run the demo scenarios with Custody off and on, and print what happened.

    python -m agent_applications.custody_demo.run                 # all, in-process
    python -m agent_applications.custody_demo.run A1 B4 -v        # some, with replies
    python -m agent_applications.custody_demo.run --custody on    # only one setting
    python -m agent_applications.custody_demo.run --json out.json # machine-readable

In-process mode needs no network, no model and no login, and is deterministic. The
evaluation (``adversarial_tests/custody_eval``) reuses :func:`run_scenarios`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from .network import DemoNetwork
from .scenarios import BY_ID, NEW_CONVERSATION, SCENARIOS, Scenario
from .settings import DemoSettings, Mode
from .world import World


@dataclass
class Result:
    scenario: str
    kind: str
    category: str
    defense: str          # "none" or "custody"
    goal_met: bool
    blocked: list[str]    # tool calls blocked (agent.tool), before any consent
    consents: int         # approvals the simulated user gave
    seconds: float
    reply: str
    expected: str | None

    @property
    def custody(self) -> bool:
        return self.defense == "custody"

    @property
    def verdict(self) -> str:
        """succeeds/stopped for attacks; done/consent/blocked/failed for benign."""
        if self.kind == "attack":
            return "succeeds" if self.goal_met else "stopped"
        if self.goal_met:
            return "consent" if self.consents else "done"
        return "blocked" if self.blocked else "failed"

    @property
    def as_expected(self) -> bool:
        return self.expected is None or self.expected == self.verdict


async def run_one(
    scenario: Scenario, *, defense: str, mode: Mode, log_dir: Path, stack=None
) -> Result:
    """One scenario under one defence. ``stack`` is the running HTTP stack, if any."""
    started = time.perf_counter()
    if stack is not None:
        stack.reset(scenario.world_definition())
        settings, world = stack.settings, World()
    else:
        settings = DemoSettings(defense=defense, mode=mode, log_dir=log_dir)
        world = scenario.world()
    net = DemoNetwork(settings, world)

    async def turn(text: str) -> str:
        target = scenario.rogue_target
        if target and scenario.special == "forged_token":
            return await net.rogue_forged(target, text)
        if target:
            return await net.rogue_says(target, text)
        return await net.ask(text)

    def refresh() -> World:
        if stack is not None:
            net.world = stack.fetch()
        return net.world

    reply = ""
    for text in scenario.turns:
        if text == NEW_CONVERSATION:
            net.new_conversation()
            continue
        reply = await turn(text)
    if scenario.special == "replay_user_request":
        reply = await net.replay_user_request()
    world = refresh()
    blocked = list(world.tool_blocks)
    consents = 0
    if scenario.approve is not None and net.pending_requests():
        consents = net.approve_pending(scenario.wants)
        if consents:
            reply = await turn(scenario.turns[-1])
            world = refresh()
    return Result(
        scenario.id, scenario.kind, scenario.category, defense,
        scenario.check(world, reply), blocked, consents,
        round(time.perf_counter() - started, 4), reply, scenario.expect.get(defense),
    )


def _defense(value: str | bool) -> str:
    if isinstance(value, bool):  # the demo's original on/off switch
        return "custody" if value else "none"
    return value


async def run_scenarios(
    scenarios: Sequence[Scenario], defenses: Sequence[str | bool], mode: Mode, log_root: Path
) -> list[Result]:
    names = [_defense(d) for d in defenses]
    results = []
    for defense in names:
        label = defense
        if mode == "http":
            from .serve import Stack

            with Stack(defense, log_root / label) as stack:
                for scenario in scenarios:
                    results.append(await run_one(
                        scenario, defense=defense, mode=mode, log_dir=log_root / label,
                        stack=stack))
        else:
            for scenario in scenarios:
                results.append(await run_one(
                    scenario, defense=defense, mode=mode,
                    log_dir=log_root / label / scenario.id))
    order = {s.id: n for n, s in enumerate(scenarios)}
    rank = {d: n for n, d in enumerate(names)}
    return sorted(results, key=lambda r: (order[r.scenario], rank[r.defense]))


async def run(ids: list[str], defenses: list, mode: Mode, log_root: Path) -> list[Result]:
    """The demo's own showcase scenarios."""
    return await run_scenarios([BY_ID[i] for i in ids] if ids else SCENARIOS,
                               defenses, mode, log_root)


LABELS = {"succeeds": "ATTACK WORKED", "stopped": "stopped", "done": "done",
          "consent": "done (after consent)", "blocked": "BLOCKED", "failed": "FAILED"}


def print_table(results: list[Result], verbose: bool, titles: dict[str, str]) -> None:
    by_id: dict[str, dict[bool, Result]] = {}
    for r in results:
        by_id.setdefault(r.scenario, {})[r.custody] = r
    print(f"{'id':<5} {'kind':<7} {'scenario':<58} {'custody off':<16} {'custody on'}")
    print("-" * 113)
    for sid, runs in by_id.items():
        first = next(iter(runs.values()))
        cells = []
        for custody in (False, True):
            r = runs.get(custody)
            cells.append("-" if r is None else LABELS[r.verdict] + ("" if r.as_expected else " (!)"))
        print(f"{sid:<5} {first.kind:<7} {titles.get(sid, '')[:58]:<58} {cells[0]:<16} {cells[1]}")
        if verbose:
            for custody, r in runs.items():
                label = "on " if custody else "off"
                for line in r.reply.splitlines() or [""]:
                    print(f"        [{label}] {line}")
                if r.blocked:
                    print(f"        [{label}] blocked tools: {', '.join(r.blocked)}")
    for label, custody in (("custody off", False), ("custody on", True)):
        group = [r for r in results if r.custody == custody]
        attacks = [r for r in group if r.kind == "attack"]
        benign = [r for r in group if r.kind == "benign"]
        if group:
            print(
                f"{label}: attacks succeeded {sum(r.goal_met for r in attacks)}/{len(attacks)}, "
                f"benign done {sum(r.goal_met for r in benign)}/{len(benign)} "
                f"({sum(1 for r in benign if r.consents)} needed consent)"
            )
    unexpected = [r for r in results if not r.as_expected]
    if unexpected:
        print("unexpected: " + ", ".join(f"{r.scenario}/{r.defense}={r.verdict}" for r in unexpected))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ids", nargs="*", help="scenario ids (default: all)")
    parser.add_argument("--custody", choices=["on", "off", "both"], default="both")
    parser.add_argument("--mode", choices=["inproc", "http"], default="inproc",
                        help="http: every agent and signer in its own process "
                             "(ports 8101-8106 and 47100-47105)")
    parser.add_argument("--logs", help="directory for decision logs (default: a temp dir)")
    parser.add_argument("--json", help="write results as JSON to this file")
    parser.add_argument("-v", "--verbose", action="store_true", help="show replies")
    args = parser.parse_args(argv)
    unknown = [i for i in args.ids if i not in BY_ID]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    defenses = {"on": [True], "off": [False], "both": [False, True]}[args.custody]
    log_root = Path(args.logs) if args.logs else Path(tempfile.mkdtemp(prefix="custody_demo_"))
    results = asyncio.run(run(args.ids, defenses, args.mode, log_root))
    print_table(results, args.verbose, {s.id: s.title for s in SCENARIOS})
    print(f"decision logs: {log_root}")
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(r) for r in results], indent=2))
    return 0 if all(r.as_expected for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
