"""The decision at the moment of power (Type-3: agent to tools).

Before a sensitive tool runs, every principal in the task's custody set must be
allowed by that tool's policy. Otherwise the call is blocked, with a reason that
names the offending principals, unless the task carries a valid one-time consent
token for exactly this call. After a tool runs, outside content it returned (mail,
web pages, files) is tagged into the task's custody set.

Policy (TOML, under the agent's own config)::

    [custody_guard.policy.pay]
    allowed = ["user:*", "agent:acme/assistant", "agent:acme/user-client", "agent:fin/*"]

    [custody_guard.sources.read_inbox]
    result_field = "from"          # each sender becomes external:h:<hash>
    [custody_guard.sources.fetch_url]
    principals = ["external:web"]  # fixed tag

Tools with no policy entry are not sensitive and always run. ``unknown`` matches
only a pattern that is exactly ``unknown`` or ``*``.

Integrations: :meth:`CustodyToolGuard.wrap` for any async tool function (LangChain
``@tool``, Claude SDK in-process MCP tools), and :meth:`CustodyToolGuard.claude_hooks`
for Claude Agent SDK ``PreToolUse``/``PostToolUse`` hooks.
"""

from __future__ import annotations

import fnmatch
import functools
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .consent import ConsentVerifier, args_digest
from .keys import load_public_key
from .replay import ReplayCache
from .store import UNKNOWN, CustodyStore, DecisionLog, custody_store
from .token import CustodyTokenError, agent_org, hash_principal, validate_principal


class CustodyToolBlocked(PermissionError):
    def __init__(self, decision: "ToolDecision") -> None:
        self.decision = decision
        super().__init__(decision.reason)


@dataclass(frozen=True, slots=True)
class ToolDecision:
    allowed: bool
    tool: str
    scope: str | None
    principals: frozenset[str]
    offenders: tuple[str, ...] = ()
    consented_by: str | None = None
    args_digest: str = ""
    reason: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "tool": self.tool,
            "offenders": list(self.offenders),
            "consented_by": self.consented_by,
            "args_digest": self.args_digest,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class SourceRule:
    principals: tuple[str, ...] = ()
    result_field: str | None = None

    def __post_init__(self) -> None:
        for principal in self.principals:
            validate_principal(principal)


def _matches(principal: str, pattern: str) -> bool:
    if principal == UNKNOWN:
        return pattern in {UNKNOWN, "*"}
    return fnmatch.fnmatchcase(principal, pattern)


def _field_values(result: Any, name: str) -> list[str]:
    """Collect ``name`` from a dict result or a list of dict results."""
    items = result if isinstance(result, list) else [result]
    values: list[str] = []
    for item in items:
        if isinstance(item, Mapping) and name in item:
            value = item[name]
            values.extend(str(v) for v in (value if isinstance(value, list) else [value]))
    return values


class CustodyToolGuard:
    def __init__(
        self,
        identity: str,
        policy: Mapping[str, Mapping[str, Any]],
        *,
        sources: Mapping[str, Mapping[str, Any]] | None = None,
        approvers: Mapping[str, str | Ed25519PublicKey] | None = None,
        principal_salt: str | bytes = b"",
        log_path: str | None = None,
        store: CustodyStore | None = None,
        replay_cache: ReplayCache | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        agent_org(identity)
        self.identity = identity
        self._allowed: dict[str, tuple[str, ...]] = {}
        self._consentable: dict[str, bool] = {}
        for tool, rule in policy.items():
            allowed = rule.get("allowed")
            if not isinstance(allowed, list) or not all(isinstance(p, str) for p in allowed):
                raise ValueError(f"policy.{tool}.allowed must be a list of patterns.")
            self._allowed[tool] = tuple(allowed)
            self._consentable[tool] = bool(rule.get("consent", True))
        self._sources = {
            tool: SourceRule(tuple(rule.get("principals", ())), rule.get("result_field"))
            for tool, rule in (sources or {}).items()
        }
        self._salt = principal_salt.encode() if isinstance(principal_salt, str) else principal_salt
        keys = {
            name: key if isinstance(key, Ed25519PublicKey) else load_public_key(key)
            for name, key in (approvers or {}).items()
        }
        self._consent = ConsentVerifier(
            identity, keys, replay_cache if replay_cache is not None else ReplayCache(clock=clock),
            clock=clock,
        )
        self.store = store if store is not None else custody_store(identity)
        self.log = DecisionLog(log_path)

    @classmethod
    def from_config(cls, section: Mapping[str, Any], **overrides: Any) -> "CustodyToolGuard":
        """Build from a ``[custody_guard]`` table (identity, policy, sources, approvers...)."""
        options = {k: v for k, v in section.items()}
        options.update(overrides)
        identity = options.pop("identity")
        policy = options.pop("policy", {})
        return cls(identity, policy, **options)

    def is_sensitive(self, tool: str) -> bool:
        return tool in self._allowed

    # ---------------------------------------------------------------- before

    def check(self, scope: str | None, tool: str, args: Mapping[str, Any]) -> ToolDecision:
        """Decide one call. Consumes a matching consent token if one is used."""
        principals = self.store.principals(scope)
        digest = args_digest(args)
        if tool not in self._allowed:
            return ToolDecision(True, tool, scope, principals, args_digest=digest)
        patterns = self._allowed[tool]
        offenders = tuple(
            sorted(p for p in principals if not any(_matches(p, pat) for pat in patterns))
        )
        if not principals:
            # Nothing is known about this task: fail closed, as for unknown.
            offenders = (UNKNOWN,)
        if not offenders:
            decision = ToolDecision(True, tool, scope, principals, args_digest=digest,
                                    reason="all influencing principals are allowed")
        else:
            approver = self._use_consent(scope, tool, args) if self._consentable[tool] else None
            if approver is not None:
                decision = ToolDecision(
                    True, tool, scope, principals, offenders, approver, digest,
                    f"one-time consent by {approver}",
                )
            else:
                decision = ToolDecision(
                    False, tool, scope, principals, offenders, None, digest,
                    f"custody: {tool} blocked; influenced by principals not allowed to "
                    f"request it: {', '.join(offenders)}. "
                    + ("A one-time user approval of this exact call is required."
                       if self._consentable[tool] else "Consent cannot override this tool."),
                )
        self.log.write(
            identity=self.identity, point="tool", scope=scope, tool=tool,
            action="consent" if decision.consented_by else ("allow" if decision.allowed else "block"),
            principals=sorted(principals), offenders=list(decision.offenders),
            args_digest=digest, consented_by=decision.consented_by,
        )
        return decision

    def _use_consent(self, scope: str | None, tool: str, args: Mapping[str, Any]) -> str | None:
        for token in self.store.consents(scope):
            try:
                claims = self._consent.matches(token, tool, args)
            except CustodyTokenError:
                continue
            self.store.discard_consent(scope, token)
            return claims.principal
        return None

    # ----------------------------------------------------------------- after

    def tag(
        self, scope: str | None, tool: str, args: Mapping[str, Any], result: Any
    ) -> frozenset[str]:
        """Add the principals behind a tool's result to the task (PostToolUse)."""
        rule = self._sources.get(tool)
        if rule is None:
            return frozenset()
        added = set(rule.principals)
        if rule.result_field:
            values = _field_values(result, rule.result_field)
            added |= {hash_principal("external", v.strip().casefold(), self._salt) for v in values}
            if not values:
                added.add(UNKNOWN)  # a source tool whose authors we cannot name
        total = self.store.add(scope, added)
        self.log.write(identity=self.identity, point="tool_result", scope=scope, tool=tool,
                       action="tag", added=sorted(added), principals=sorted(total))
        return frozenset(added)

    # ---------------------------------------------------------- integrations

    def wrap(
        self,
        fn: Callable[..., Awaitable[Any]],
        *,
        tool: str,
        scope: str | None,
        on_block: Callable[[ToolDecision], Any] | None = None,
        single_dict_arg: bool = False,
    ) -> Callable[..., Awaitable[Any]]:
        """Guard an async tool function bound to one task.

        ``single_dict_arg`` is for Claude SDK tools, which take one ``arguments``
        dict; otherwise keyword arguments are the tool arguments (LangChain).
        On a block, ``on_block(decision)`` is returned to the model if given,
        else :class:`CustodyToolBlocked` is raised.
        """

        @functools.wraps(fn)
        async def guarded(*a: Any, **kw: Any) -> Any:
            args = dict(a[0]) if single_dict_arg else dict(kw)
            if not single_dict_arg and a:
                raise TypeError("Guarded tools take keyword arguments only.")
            decision = self.check(scope, tool, args)
            if not decision.allowed:
                if on_block is not None:
                    return on_block(decision)
                raise CustodyToolBlocked(decision)
            result = await fn(*a, **kw)
            self.tag(scope, tool, args, result)
            return result

        return guarded

    def claude_hooks(self, scope: str | None) -> dict[str, list[Any]]:
        """``hooks=`` for ``ClaudeAgentOptions``, bound to one task (inbound session)."""
        from claude_agent_sdk import HookMatcher

        async def pre(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict:
            decision = self.check(scope, input_data["tool_name"], input_data.get("tool_input") or {})
            if decision.allowed:
                return {}
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": decision.reason,
                }
            }

        async def post(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict:
            self.tag(
                scope,
                input_data["tool_name"],
                input_data.get("tool_input") or {},
                _claude_result(input_data.get("tool_response")),
            )
            return {}

        return {
            "PreToolUse": [HookMatcher(hooks=[pre])],
            "PostToolUse": [HookMatcher(hooks=[post])],
        }


def _claude_result(response: Any) -> Any:
    """Claude MCP tool results wrap JSON in text blocks; unwrap for field tagging."""
    import json

    if isinstance(response, Mapping) and isinstance(response.get("content"), list):
        out: list[Any] = []
        for block in response["content"]:
            text = block.get("text") if isinstance(block, Mapping) else None
            try:
                out.append(json.loads(text) if isinstance(text, str) else block)
            except json.JSONDecodeError:
                out.append(block)
        return out[0] if len(out) == 1 else out
    return response
