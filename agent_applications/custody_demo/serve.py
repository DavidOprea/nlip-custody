"""HTTP mode: every agent and every signer in its own OS process.

``run.py --mode http`` uses :class:`Stack` to start, per custody setting:

* one custody signer process per identity (``security_extensions.custody.signer``),
  each with its own random authkey, so an agent can only reach its own signer;
* one uvicorn process per agent, given only its own signer's authkey.

The runner process plays the user's client (and the rogue's client). Each agent
also exposes ``/demo/reset`` and ``/demo/world`` so the runner can load a scenario's
mock world and read the outcome; these are demo plumbing, not part of NLIP.

Run one agent by hand::

    python -m agent_applications.custody_demo.serve finance --custody on
"""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import httpx

from .agents import AGENTS
from .scenarios import BY_ID
from .settings import DemoSettings, key_filename
from .world import ConsentRequest, Payment, World

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHKEY_ENV = "CUSTODY_SIGNER_AUTHKEY"


def build_app(name: str, custody: bool, log_dir: str | None = None):
    settings = DemoSettings(custody=custody, mode="http", log_dir=log_dir)
    world = World()
    agent = AGENTS[name](name, settings, world)
    app = agent.create_nlip_app()

    @app.post("/demo/reset")
    async def reset(body: dict) -> dict:
        fresh = BY_ID[body["scenario"]].world()
        for key, value in vars(fresh).items():
            setattr(world, key, value)
        return {"ok": True}

    @app.get("/demo/world")
    async def state() -> dict:
        return asdict(world)

    return app, settings


def world_from_json(data: dict) -> World:
    world = World()
    world.ledger = [Payment(**p) for p in data["ledger"]]
    world.salary_reads = list(data["salary_reads"])
    world.rogue_received = list(data["rogue_received"])
    world.tool_blocks = list(data["tool_blocks"])
    world.consent_requests = [
        ConsentRequest(r["agent"], r["tool"], r["args"], tuple(r["offenders"]))
        for r in data["consent_requests"]
    ]
    return world


class Stack:
    """Start signers and agents as subprocesses; stop them on exit."""

    def __init__(self, custody: bool, log_dir: Path) -> None:
        self.custody = custody
        self.log_dir = log_dir
        self.settings = DemoSettings(custody=custody, mode="http", log_dir=log_dir)
        self.procs: list[subprocess.Popen] = []
        self.labels: list[str] = []
        self.authkeys = {i: secrets.token_urlsafe(32) for i in self.settings.identities.values()}
        self.http = httpx.Client(timeout=10)  # one pool for control calls

    def _spawn(self, label: str, args: list[str], authkey: str | None) -> None:
        env = {k: v for k, v in os.environ.items() if k != AUTHKEY_ENV}
        if authkey is not None:
            env[AUTHKEY_ENV] = authkey
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with (self.log_dir / f"{label}.stderr.log").open("wb") as log:
            self.procs.append(subprocess.Popen(
                [sys.executable, *args], cwd=REPO_ROOT, env=env,
                stdout=subprocess.DEVNULL, stderr=log,
            ))
        self.labels.append(label)

    def __enter__(self) -> "Stack":
        s = self.settings
        try:
            if self.custody:
                for identity in s.identities.values():
                    self._spawn(f"signer_{key_filename(identity)[:-4]}", [
                        "-m", "security_extensions.custody.signer", "--identity", identity,
                        "--key", str(s.keys_dir / key_filename(identity)),
                        "--address", s.signer_address(identity),
                    ], self.authkeys[identity])
            for name in AGENTS:
                identity = s.identities.get(name)
                self._spawn(f"agent_{name}", [
                    "-m", "agent_applications.custody_demo.serve", name,
                    "--custody", "on" if self.custody else "off", "--logs", str(self.log_dir),
                ], self.authkeys.get(identity) if (self.custody and identity) else None)
            self._wait_ready()
        except BaseException:
            self.__exit__()
            raise
        # The runner process is the user's client: give it only the user's signer key.
        if self.custody:
            os.environ[AUTHKEY_ENV] = self.authkeys[s.user_identity]
        return self

    def _wait_ready(self, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        for name in AGENTS:
            url = self.settings.entity(name)["endpoint"].removesuffix("/nlip") + "/health"
            while True:
                for label, proc in zip(self.labels, self.procs):
                    if proc.poll() is not None:
                        err = (self.log_dir / f"{label}.stderr.log").read_text(errors="replace")
                        raise RuntimeError(f"{label} exited early:\n{err[-2000:]}")
                try:
                    if self.http.get(url, timeout=1).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError(f"{name} did not start at {url}")
                time.sleep(0.2)

    def __exit__(self, *_: object) -> None:
        os.environ.pop(AUTHKEY_ENV, None)
        for proc in self.procs:
            proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.procs.clear()
        self.labels.clear()
        self.http.close()

    # ---------------------------------------------------------- scenario I/O

    def _base(self, name: str) -> str:
        return self.settings.entity(name)["endpoint"].removesuffix("/nlip")

    def reset(self, scenario: str) -> None:
        for name in AGENTS:
            self.http.post(f"{self._base(name)}/demo/reset",
                           json={"scenario": scenario}).raise_for_status()

    def fetch(self) -> World:
        merged = World()
        for name in AGENTS:
            part = world_from_json(self.http.get(f"{self._base(name)}/demo/world").json())
            merged.ledger += part.ledger
            merged.salary_reads += part.salary_reads
            merged.rogue_received += part.rogue_received
            merged.tool_blocks += part.tool_blocks
            merged.consent_requests += part.consent_requests
        return merged


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Serve one demo agent over HTTP.")
    parser.add_argument("name", choices=sorted(AGENTS))
    parser.add_argument("--custody", choices=["on", "off"], default="on")
    parser.add_argument("--logs", default=None)
    args = parser.parse_args(argv)
    import uvicorn

    app, settings = build_app(args.name, args.custody == "on", args.logs)
    entity = settings.entity(args.name)
    uvicorn.run(app, host=entity["host"], port=entity["port"], log_level="warning")


if __name__ == "__main__":
    main()
