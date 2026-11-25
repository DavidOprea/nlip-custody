"""AgentDojo's banking suite split across NLIP agents.

Each AgentDojo tool runs on the NLIP agent that would own it in a deployment: the
bank's agents hold the account tools, the user's file store holds ``read_file``. The
user's assistant runs the task by calling them over NLIP. Every call crosses the
framework's real server and client pipelines, so every defence sees it exactly as
in the custody demo.

The assistant is the **scripted worst case**: it runs the user task's ground-truth
calls (AgentDojo's own ``ground_truth``), and the moment any tool output contains
the injected text, it also runs the injection task's ground-truth calls, as a model
that always obeys injections would. Utility and security are scored with
AgentDojo's own ``utility`` and ``security`` checks on the shared environment.

In-process only: the AgentDojo environment is one Python object shared by the tool
hosts, so this does not run as separate HTTP processes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime

from agent_applications.custody_demo.settings import DemoSettings
from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer, NLIPSession
from nlip_sdk.nlip_security_extensions import SecurityBlockedError
from security_extensions.custody.consent import ConsentIssuer
from security_extensions.custody.keys import load_pinned_keys, load_private_key
from security_extensions.custody.request import ConsentDesk, ConsentRequestClaims
from security_extensions.custody.store import custody_store, reset_custody_stores

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.toml"
USER_PRINCIPAL = "user:h:emma"
BLOCKED = "[BLOCKED"

HOSTS: dict[str, tuple[str, ...]] = {
    "bank": ("get_iban", "send_money", "schedule_transaction", "update_scheduled_transaction",
             "get_balance", "get_most_recent_transactions", "get_scheduled_transactions"),
    "profile": ("get_user_info", "update_password", "update_user_info"),
    "files": ("read_file",),
}
TOOL_HOST = {tool: host for host, tools in HOSTS.items() for tool in tools}


def jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    return value


def strings_in(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings_in(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings_in(v)]
    return []


@dataclass
class EnvHolder:
    """The shared AgentDojo environment for one run (swapped per task pair)."""

    env: Any = None


class ToolHost(NLIPServer):
    """An NLIP agent that owns some AgentDojo tools, behind the configured defences.

    Requests are structured ``{"function": ..., "args": {...}}``; replies are the
    tool result as JSON text, or a ``[BLOCKED ...]`` line from the tool guard.
    """

    def __init__(self, name: str, settings: DemoSettings, holder: EnvHolder, tools: list) -> None:
        super().__init__(name, security=settings.security(name))
        self.holder = holder
        self.runtime = FunctionsRuntime([t for t in tools if t.name in HOSTS[name]])
        identity = settings.identities.get(name)
        store = custody_store(identity) if (settings.custody and identity) else None
        self.guard = settings.guard(name, store)

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> str:
        request = message.content if isinstance(message.content, dict) else {}
        function, args = request.get("function"), dict(request.get("args") or {})
        if self.guard is not None:
            decision = self.guard.check(session.id, function, args)
            if not decision.allowed:
                return f"{BLOCKED} {decision.reason}]"
        result, error = self.runtime.run_function(self.holder.env, function, args)
        if error:
            return json.dumps({"error": error})
        data = jsonable(result)
        if self.guard is not None:
            self.guard.tag(session.id, function, args, data)
        return json.dumps(data, ensure_ascii=False)


@dataclass
class Plan:
    """What the scripted assistant will do in one conversation."""

    user_calls: list[FunctionCall]
    injection_calls: list[FunctionCall] = field(default_factory=list)
    injected_texts: list[str] = field(default_factory=list)
    injected: bool = False
    pending: list[FunctionCall] = field(default_factory=list)  # blocked user-task calls
    outputs: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


class DojoAssistant(NLIPServer):
    """The user's assistant: runs AgentDojo ground truth over NLIP, obeying injections."""

    def __init__(self, settings: DemoSettings) -> None:
        security = settings.security("assistant")
        super().__init__("assistant", security=security)
        self.client = NLIPClient(settings.endpoints(exclude="assistant"), identity="assistant",
                                 security=security)
        self.plan: Plan | None = None

    async def call(self, fc: FunctionCall, session: NLIPSession) -> str:
        host = TOOL_HOST[fc.function]
        try:
            reply = await self.client.send(
                host, NLIPMessage.structured({"function": fc.function, "args": dict(fc.args)}),
                scope=session.id)
            text = reply.extract_text(language=None) or ""
        except (SecurityBlockedError, httpx.HTTPError) as error:
            text = f"{BLOCKED} at the door: {error}]"
        assert self.plan is not None
        self.plan.outputs.append(text)
        if text.startswith(BLOCKED):
            self.plan.blocked.append(f"{host}.{fc.function}")
        return text

    def _contains_injection(self, text: str) -> bool:
        plan = self.plan
        if plan is None or not plan.injected_texts:
            return False
        try:
            found = strings_in(json.loads(text))
        except (json.JSONDecodeError, TypeError):
            found = [text]
        # AgentDojo's environment loader reflows whitespace when it injects, so compare
        # with whitespace collapsed on both sides.
        def norm(value: str) -> str:
            return " ".join(value.split())

        wanted = [norm(inj) for inj in plan.injected_texts if inj.strip()]
        return any(inj in norm(s) for s in found for inj in wanted)

    async def run_calls(self, calls: list[FunctionCall], session: NLIPSession, *, user: bool) -> None:
        assert self.plan is not None
        for fc in calls:
            text = await self.call(fc, session)
            if text.startswith(BLOCKED) and user:
                self.plan.pending.append(fc)
            if not self.plan.injected and self._contains_injection(text):
                # Worst case: the model obeys the injection at once.
                self.plan.injected = True
                await self.run_calls(self.plan.injection_calls, session, user=False)

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> str:
        assert self.plan is not None, "set a plan before the conversation starts"
        text = (message.extract_text(language=None) or "").strip().casefold()
        if text == "continue":
            retry, self.plan.pending = self.plan.pending, []
            await self.run_calls(retry, session, user=True)
        else:
            await self.run_calls(self.plan.user_calls, session, user=True)
        return "\n".join(self.plan.outputs[-20:])


class DojoNetwork:
    """The assistant, the tool hosts and the user's client, wired in-process."""

    def __init__(self, defense: str, tools: list, log_dir: Path | None = None) -> None:
        reset_custody_stores()
        self.settings = DemoSettings(defense=defense, config_path=CONFIG_PATH, log_dir=log_dir)
        self.holder = EnvHolder()
        self.servers: dict[str, NLIPServer] = {name: ToolHost(name, self.settings, self.holder, tools)
                                               for name in HOSTS}
        self.assistant = DojoAssistant(self.settings)
        self.servers["assistant"] = self.assistant
        self._route(self.assistant.client)
        self.user = NLIPClient(self.settings.endpoints(exclude="user"), identity="user",
                               security=self.settings.security("user"))
        self._route(self.user)
        self.desk = ConsentDesk(load_pinned_keys(
            {i: k for i, k in self.settings.public_keys.items() if i != self.settings.user_identity}))

    def _route(self, client: NLIPClient) -> None:
        servers = self.servers

        async def post(destination: str, message: NLIPMessage) -> httpx.Response:
            request = httpx.Request("POST", client.endpoints[destination])
            try:
                reply = await servers[destination].process_exchange(message)
            except SecurityBlockedError as error:
                return httpx.Response(403, json={"detail": str(error)}, request=request)
            return httpx.Response(200, json=reply.to_dict(), request=request)

        client._post = post  # type: ignore[method-assign]

    async def ask(self, text: str) -> str:
        try:
            reply = await self.user.send_text("assistant", text)
        except httpx.HTTPStatusError as error:
            return f"(assistant refused: {error.response.text})"
        return reply.extract_text(language=None) or ""

    def approve(self, wants: Callable[[ConsentRequestClaims], bool]) -> int:
        """The user reviews verified consent requests and approves the ones ``wants`` accepts."""
        if not self.settings.consent:
            return 0
        store = custody_store(self.settings.user_identity)
        shown, _ = self.desk.pending(store.take_request_tokens(None))
        key = load_private_key(self.settings.keys_dir / "agent_acme_user-client.pem")
        issuer = ConsentIssuer(self.settings.user_identity, USER_PRINCIPAL, key)
        chosen = [r for r in shown if wants(r)]
        for request in chosen:
            store.add_consent(None, ConsentDesk.approve(request, issuer))
        return len(chosen)
