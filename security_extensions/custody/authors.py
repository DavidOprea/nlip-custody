"""Authors of stored objects: influence that survives a conversation.

An agent can be told something in one conversation, write it to memory, a file or a
database, and act on it in a later conversation that looks clean. Per-conversation
custody sets alone would lose the link (the "laundering through storage" attack;
FIDES-across-sessions reports labels lost in most cases at a second session).

So when a tool *writes* an object, the tool guard records the writing task's full
principal set as that object's authors, here. When a later task *reads* the object,
the guard adds those authors to the reading task. The metadata lives in the guard,
outside the model and outside the storage the model's tools can touch.

Objects are named ``<namespace>:<key>``, e.g. ``memory:standing-order``. A write
replaces the authors (``mode="replace"``) or adds to them (``mode="append"``). An
object that exists but has no recorded authors was written by something Custody did
not see, and reads as ``unknown``.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Iterable
from pathlib import Path

from .token import validate_principal


class AuthorStore:
    """``object -> frozenset of principals``, optionally persisted to a JSON file."""

    def __init__(self, path: str | os.PathLike[str] | None = None, *, max_objects: int = 100_000):
        self._path = Path(path) if path else None
        self._max = max_objects
        self._authors: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        if self._path is not None and self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._authors = {k: {validate_principal(p) for p in v} for k, v in data.items()}

    def __len__(self) -> int:
        return len(self._authors)

    def record(self, obj: str, principals: Iterable[str], *, mode: str = "replace") -> frozenset[str]:
        new = {validate_principal(p) for p in principals}
        with self._lock:
            if mode == "append":
                self._authors.setdefault(obj, set()).update(new)
            elif mode == "replace":
                self._authors[obj] = new
            else:
                raise ValueError("mode must be 'replace' or 'append'.")
            if len(self._authors) > self._max:
                raise RuntimeError("Author store full; refusing to forget authors.")
            result = frozenset(self._authors[obj])
            self._save()
        return result

    def authors(self, obj: str) -> frozenset[str] | None:
        """The recorded authors, or ``None`` if nothing was recorded for ``obj``."""
        with self._lock:
            found = self._authors.get(obj)
            return None if found is None else frozenset(found)

    def forget(self, obj: str) -> None:
        with self._lock:
            self._authors.pop(obj, None)
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._authors.clear()
            self._save()

    def _save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps({k: sorted(v) for k, v in sorted(self._authors.items())}, indent=1)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".authors-")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp, self._path)  # atomic: a crash never leaves half a file


_STORES: dict[str, AuthorStore] = {}
_STORES_LOCK = threading.Lock()


def author_store(identity: str, path: str | os.PathLike[str] | None = None) -> AuthorStore:
    """The process-wide author store for one agent identity (created on first use)."""
    with _STORES_LOCK:
        if identity not in _STORES:
            _STORES[identity] = AuthorStore(path)
        return _STORES[identity]


def reset_author_stores() -> None:
    with _STORES_LOCK:
        _STORES.clear()
