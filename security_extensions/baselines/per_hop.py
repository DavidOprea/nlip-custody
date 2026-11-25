"""Baseline: per-agent taint with no propagation (Rule of Two style).

Each agent tracks taint for its own conversations only:

* principals it observed itself: tool results its own hooks tagged, the verified
  identity of whoever called it or replied to it, ``unknown`` for unsigned peers;
* nothing from upstream: tokens authenticate the sender but carry no principal set.

The same tool policy as Custody is applied to that local view. On top, the Rule of
Two: a conversation that has seen untrusted input *and* sensitive data may not send
to an outside destination.

What this cannot see, by construction: an injection that reached a *different*
agent earlier in the chain. That is the gap Custody's propagation closes.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from nlip_sdk.nlip_security_extensions import SecurityDecision, SecurityEvent

from security_extensions.custody.extension import CustodyExtension
from security_extensions.custody.store import UNKNOWN


def _untrusted(principals: Collection[str]) -> bool:
    return any(p == UNKNOWN or p.startswith("external:") for p in principals)


class PerHopTaintExtension(CustodyExtension):
    def __init__(
        self,
        identity: str,
        *,
        sensitive_sources: Collection[str] = (),
        outside_destinations: Collection[str] = (),
        **options: Any,
    ) -> None:
        options["propagate"] = False
        super().__init__(identity, **options)
        self._sensitive_sources = {s.casefold() for s in sensitive_sources}
        self._outside = {d.casefold() for d in outside_destinations}
        self._sensitive_scopes: set[str | None] = set()

    async def _client_ingress(self, event: SecurityEvent) -> SecurityDecision:
        if (event.session.peer or "").casefold() in self._sensitive_sources:
            self._sensitive_scopes.add(event.scope)
        return await super()._client_ingress(event)

    async def _client_egress(self, event: SecurityEvent) -> SecurityDecision:
        destination = (event.session.peer or "").casefold()
        if (
            destination in self._outside
            and event.scope in self._sensitive_scopes
            and _untrusted(self.store.principals(event.scope))
        ):
            self._record(event, "block", reason="rule of two")
            return SecurityDecision.block(
                "rule of two: untrusted input and sensitive data in this conversation; "
                f"refusing to send to outside destination {destination}"
            )
        return await super()._client_egress(event)
