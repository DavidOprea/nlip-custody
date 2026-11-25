"""Baseline: authority narrowing (Warrant style).

The user delegates bounded authority to named agents; a tool call runs only if the
verified caller holds a warrant for that tool and the arguments are within its caps.
Authentication, replay protection and audience binding come from the same signed
sender tokens Custody uses (with ``propagate=False``).

What this checks: *who is asking* and *how much*. What it cannot see: who shaped the
request. A hijacked delegate acting within its caps passes, which is the residual
risk Warrant's own README lists as "R1 in-bound misuse".

Config (per guarded tool)::

    [authority.finance.warrants.pay]
    holders = ["agent:acme/assistant", "agent:fin/*"]
    max = { amount = 10000 }
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from typing import Any

from security_extensions.custody.consent import args_digest
from security_extensions.custody.guard import CustodyToolGuard, ToolDecision
from security_extensions.custody.store import UNKNOWN


class AuthorityGuard(CustodyToolGuard):
    def __init__(
        self,
        identity: str,
        warrants: Mapping[str, Mapping[str, Any]],
        **options: Any,
    ) -> None:
        options.pop("policy", None)
        options.pop("approvers", None)  # warrants have no per-call user consent
        super().__init__(identity, {tool: {"allowed": ["*"]} for tool in warrants}, **options)
        self._warrants = {
            tool: (tuple(w.get("holders", ())), dict(w.get("max", {})))
            for tool, w in warrants.items()
        }

    @classmethod
    def from_config(cls, section: Mapping[str, Any], **overrides: Any) -> "AuthorityGuard":
        options = {**section, **overrides}
        return cls(options.pop("identity"), options.pop("warrants"), **options)

    def check(self, scope: str | None, tool: str, args: Mapping[str, Any]) -> ToolDecision:
        principals = self.store.principals(scope)
        digest = args_digest(args)
        if tool not in self._warrants:
            return ToolDecision(True, tool, scope, principals, args_digest=digest)
        holders, caps = self._warrants[tool]
        # With propagate=False the task's set holds only verified senders (or unknown).
        callers = sorted(p for p in principals if p.startswith("agent:") or p == UNKNOWN)
        problems = [
            f"{c} holds no warrant for {tool}" for c in callers
            if c == UNKNOWN or not any(fnmatch.fnmatchcase(c, h) for h in holders)
        ]
        if not callers:
            problems.append("no authenticated caller")
        for key, limit in caps.items():
            try:
                if float(args.get(key, 0)) > float(limit):
                    problems.append(f"{key}={args.get(key)} exceeds the warrant cap {limit}")
            except (TypeError, ValueError):
                problems.append(f"{key} is not a number")
        allowed = not problems
        decision = ToolDecision(
            allowed, tool, scope, principals, tuple(callers) if not allowed else (), None,
            digest, "within delegated authority" if allowed
            else f"authority: {tool} blocked; " + "; ".join(problems),
        )
        self.log.write(identity=self.identity, point="tool", scope=scope, tool=tool,
                       action="allow" if allowed else "block", principals=sorted(principals),
                       reason=decision.reason, args_digest=digest)
        return decision
