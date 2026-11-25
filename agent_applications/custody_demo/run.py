"""Run the demo scenarios with Custody off and on, and print what happened.

    python -m agent_applications.custody_demo.run                 # all, in-process
    python -m agent_applications.custody_demo.run A1 B4 -v        # some, with replies
    python -m agent_applications.custody_demo.run --custody on    # only one setting
    python -m agent_applications.custody_demo.run --json out.json # machine-readable

In-process mode needs no network, no model and no login, and is deterministic.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .network import DemoNetwork
from .scenarios import BY_ID, SCENARIOS, Scenario
from .settings import DemoSettings, Mode
from .world import World


@dataclass
class Result:
    scenario: str
    kind: str
    custody: bool
    goal_met: bool
    blocked: list[str]
    consents: int
    reply: str

    @property
    def verdict(self) -> str:
        if self.kind == "attack":
            return "ATTACK WORKED" if self.goal_met else "stopped"
        if not self.goal_met:
            return "FAILED"
        return "done (after consent)" if self.consents else "done"


async def run_one(
    scenario: Scenario, *, custody: bool, mode: Mode, log_dir: Path, stack=None
) -> Result:
    """One scenario, one custody setting. ``stack`` is the running HTTP stack, if any."""
    if stack is not None:
        stack.reset(scenario.id)
        settings, world = stack.settings, World()
    else:
        settings = DemoSettings(custody=custody, mode=mode, log_dir=log_dir)
        world = scenario.world()
    net = DemoNetwork(settings, world)

    async def act() -> str:
        if scenario.from_rogue_to:
            return await net.rogue_says(scenario.from_rogue_to, scenario.prompt)
        return await net.ask(scenario.prompt)

    reply = await act()
    if stack is not None:
        net.world = world = stack.fetch()
    blocked = list(world.tool_blocks)
    consents = 0
    if scenario.user_approves and world.consent_requests:
        consents = net.approve_pending()
        reply = await act()
        if stack is not None:
            world = stack.fetch()
    return Result(scenario.id, scenario.kind, custody, scenario.goal(world, reply),
                  blocked, consents, reply)


async def run(ids: list[str], settings: list[bool], mode: Mode, log_root: Path) -> list[Result]:
    scenarios = [BY_ID[i] for i in ids] if ids else SCENARIOS
    results = []
    for custody in settings:
        label = "custody_on" if custody else "custody_off"
        if mode == "http":
            from .serve import Stack

            with Stack(custody, log_root / label) as stack:
                for scenario in scenarios:
                    results.append(await run_one(
                        scenario, custody=custody, mode=mode, log_dir=log_root / label,
                        stack=stack))
        else:
            for scenario in scenarios:
                results.append(await run_one(
                    scenario, custody=custody, mode=mode,
                    log_dir=log_root / label / scenario.id))
    order = {s.id: n for n, s in enumerate(scenarios)}
    return sorted(results, key=lambda r: (order[r.scenario], r.custody))


def print_table(results: list[Result], verbose: bool) -> None:
    by_id: dict[str, dict[bool, Result]] = {}
    for r in results:
        by_id.setdefault(r.scenario, {})[r.custody] = r
    print(f"{'id':<4} {'kind':<7} {'scenario':<58} {'custody off':<16} {'custody on'}")
    print("-" * 112)
    for sid, runs in by_id.items():
        s = BY_ID[sid]
        off = runs.get(False).verdict if False in runs else "-"
        on = runs.get(True).verdict if True in runs else "-"
        print(f"{sid:<4} {s.kind:<7} {s.title:<58} {off:<16} {on}")
        if verbose:
            for custody, r in runs.items():
                label = "on " if custody else "off"
                for line in r.reply.splitlines() or [""]:
                    print(f"       [{label}] {line}")
                if r.blocked:
                    print(f"       [{label}] blocked tools: {', '.join(r.blocked)}")
    on = [r for r in results if r.custody]
    off = [r for r in results if not r.custody]
    for label, group in (("custody off", off), ("custody on", on)):
        attacks = [r for r in group if r.kind == "attack"]
        benign = [r for r in group if r.kind == "benign"]
        if group:
            print(
                f"{label}: attacks succeeded {sum(r.goal_met for r in attacks)}/{len(attacks)}, "
                f"benign done {sum(r.goal_met for r in benign)}/{len(benign)} "
                f"({sum(1 for r in benign if r.consents)} needed consent)"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ids", nargs="*", help="scenario ids (default: all)")
    parser.add_argument("--custody", choices=["on", "off", "both"], default="both")
    parser.add_argument("--mode", choices=["inproc", "http"], default="inproc",
                        help="http: every agent and signer in its own process "
                             "(ports 8101-8105 and 47100-47104)")
    parser.add_argument("--logs", help="directory for decision logs (default: a temp dir)")
    parser.add_argument("--json", help="write results as JSON to this file")
    parser.add_argument("-v", "--verbose", action="store_true", help="show replies")
    args = parser.parse_args(argv)
    unknown = [i for i in args.ids if i not in BY_ID]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    settings = {"on": [True], "off": [False], "both": [False, True]}[args.custody]
    log_root = Path(args.logs) if args.logs else Path(tempfile.mkdtemp(prefix="custody_demo_"))
    results = asyncio.run(run(args.ids, settings, args.mode, log_root))
    print_table(results, args.verbose)
    print(f"decision logs: {log_root}")
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(r) for r in results], indent=2))
    failed = [r for r in results if r.custody and (r.goal_met == (r.kind == "attack"))]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
