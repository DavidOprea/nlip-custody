"""Bounded nonce cache that rejects a custody token's second use."""

from __future__ import annotations

import heapq
import threading
import time
from collections.abc import Callable


class ReplayCache:
    """Remembers ``(issuer, nonce)`` until the token expires (plus clock skew).

    When the cache is full of unexpired entries it fails closed: new tokens are
    rejected rather than evicting live nonces, which would reopen replay.
    """

    def __init__(
        self,
        max_entries: int = 100_000,
        *,
        clock_skew: int = 30,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive.")
        self._max = max_entries
        self._skew = clock_skew
        self._clock = clock
        self._seen: dict[tuple[str, str], int] = {}
        self._expiry: list[tuple[int, tuple[str, str]]] = []
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def _purge(self, now: int) -> None:
        while self._expiry and self._expiry[0][0] < now:
            forget_at, key = heapq.heappop(self._expiry)
            if self._seen.get(key) == forget_at:
                del self._seen[key]

    def check_and_add(self, issuer: str, nonce: str, exp: int) -> bool:
        """Return True and record the nonce if unseen; False if replayed or full."""
        key = (issuer, nonce)
        forget_at = exp + self._skew
        with self._lock:
            self._purge(int(self._clock()))
            if key in self._seen:
                return False
            if len(self._seen) >= self._max:
                return False
            self._seen[key] = forget_at
            heapq.heappush(self._expiry, (forget_at, key))
            return True
