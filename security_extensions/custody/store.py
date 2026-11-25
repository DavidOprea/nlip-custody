"""Per-task custody sets shared by the NLIP SE and the agent's tool hooks.

A *scope* is a causal context: the inbound server session id that started the task
(the same string ``NLIPClient.send(..., scope=...)`` uses for outbound calls it
causes). ``None`` is the default scope of an originating client with no inbound
session, e.g. the user's own chat client.

The NLIP SE and the tool hooks (PreToolUse/PostToolUse, LangChain wrappers) of one
agent must use the same store. Look it up by the agent's custody identity::

    store = custody_store("agent:fin/finance")
"""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .token import validate_principal

UNKNOWN = "unknown"


class CustodyStore:
    """Bounded map ``scope -> set of principals``; principals are only ever added."""

    def __init__(self, max_scopes: int = 10_000) -> None:
        self._max = max_scopes
        self._sets: OrderedDict[str | None, set[str]] = OrderedDict()
        self._callers: dict[str | None, str | None] = {}
        # Consent tokens seen in this task: opaque here, verified by the tool guard.
        self._consents: dict[str | None, list[str]] = {}
        # Blocked calls waiting to be signed into consent requests (by the SE at
        # server egress), and signed requests from downstream waiting to be forwarded
        # upstream (or, at the user's client, shown to the user).
        self._pending_requests: dict[str | None, list[dict[str, Any]]] = {}
        self._request_tokens: dict[str | None, list[str]] = {}
        self._lock = threading.Lock()

    def add(self, scope: str | None, principals: Iterable[str]) -> frozenset[str]:
        new = {validate_principal(p) for p in principals}
        with self._lock:
            current = self._sets.setdefault(scope, set())
            current |= new
            self._sets.move_to_end(scope)
            while len(self._sets) > self._max:
                old, _ = self._sets.popitem(last=False)
                self._callers.pop(old, None)
                self._consents.pop(old, None)
            return frozenset(current)

    def principals(self, scope: str | None) -> frozenset[str]:
        with self._lock:
            return frozenset(self._sets.get(scope, ()))

    def set_caller(self, scope: str | None, caller: str | None) -> None:
        """Remember who sent the current inbound turn, to address the reply."""
        with self._lock:
            self._callers[scope] = caller

    def caller(self, scope: str | None) -> str | None:
        with self._lock:
            return self._callers.get(scope)

    def add_consent(self, scope: str | None, token: str, *, max_per_scope: int = 32) -> None:
        with self._lock:
            pool = self._consents.setdefault(scope, [])
            if token not in pool:
                pool.append(token)
                del pool[:-max_per_scope]

    def consents(self, scope: str | None) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._consents.get(scope, ()))

    def discard_consent(self, scope: str | None, token: str) -> None:
        with self._lock:
            pool = self._consents.get(scope)
            if pool and token in pool:
                pool.remove(token)

    def add_pending_request(
        self, scope: str | None, tool: str, args: dict[str, Any], offenders: Iterable[str]
    ) -> None:
        with self._lock:
            pool = self._pending_requests.setdefault(scope, [])
            entry = {"tool": tool, "args": dict(args), "offenders": sorted(offenders)}
            if entry not in pool:
                pool.append(entry)
                del pool[:-32]

    def take_pending_requests(self, scope: str | None) -> list[dict[str, Any]]:
        with self._lock:
            return self._pending_requests.pop(scope, [])

    def add_request_token(self, scope: str | None, token: str) -> None:
        with self._lock:
            pool = self._request_tokens.setdefault(scope, [])
            if token not in pool:
                pool.append(token)
                del pool[:-32]

    def request_tokens(self, scope: str | None) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._request_tokens.get(scope, ()))

    def take_request_tokens(self, scope: str | None) -> list[str]:
        with self._lock:
            return self._request_tokens.pop(scope, [])

    def clear(self, scope: str | None) -> None:
        with self._lock:
            self._sets.pop(scope, None)
            self._callers.pop(scope, None)
            self._consents.pop(scope, None)
            self._pending_requests.pop(scope, None)
            self._request_tokens.pop(scope, None)


_STORES: dict[str, CustodyStore] = {}
_STORES_LOCK = threading.Lock()


def custody_store(identity: str) -> CustodyStore:
    """The process-wide store for one agent identity (created on first use)."""
    with _STORES_LOCK:
        return _STORES.setdefault(identity, CustodyStore())


class DecisionLog:
    """Append-only JSON-lines log of custody decisions (no hash chain, by design)."""

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **entry: Any) -> None:
        if self._path is None:
            return
        entry = {"ts": round(time.time(), 3), **entry}
        line = json.dumps(entry, sort_keys=True, default=sorted, ensure_ascii=False)
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def reset_custody_stores() -> None:
    """Forget every agent's custody state (for tests and repeated demo runs)."""
    with _STORES_LOCK:
        _STORES.clear()
