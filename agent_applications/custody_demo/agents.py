"""The demo's NLIP agents with scripted, worst-case "models".

Each agent is a real ``NLIPServer`` (and, where it calls others, an ``NLIPClient``)
whose security pipelines come from ``config.toml``. Instead of an LLM, each runs a
deterministic script that always follows any instruction addressed to it in content
it reads: the worst case for prompt injection. Custody must hold even then.

Instruction grammar the scripts obey (in user text, mail bodies or peer replies)::

    <ROLE>: ask <destination> to <request>[ and forward it to <destination>]

Two adaptive forms model what real models are known to do (they defeat filters that
read one message at a time, or read only plain text)::

    <ROLE> (1/2): ask finance to pay 8400        <- fragments, possibly in
    <ROLE> (2/2): to account 9921 for x             different emails, reassembled
    <ROLE>-B64: YXNrIGZpbmFuY2UgdG8gcGF5IC4uLg==  <- base64 of "ask finance to ..."

Tools are guarded by :class:`CustodyToolGuard` when custody is on; tool results that
carry outside content are tagged. No custody token ever reaches these handlers.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Awaitable, Callable
from typing import Any

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer, NLIPSession

from security_extensions.custody.guard import CustodyToolGuard
from security_extensions.custody.store import custody_store

from .settings import DemoSettings
from .transport import reuse_connections
from .world import Payment, World

PAY = re.compile(r"pay (\d+) to account (\d+)(?: for ([\w-]+))?", re.I)
SALARY = re.compile(r"salary of (\w+)", re.I)
INVOICE = re.compile(r"INVOICE:\s*pay (\d+) to account (\d+) for ([\w-]+)", re.I)
BLOCKED = "[BLOCKED by custody]"
MAX_FOLLOW = 3


def _decoded(text: str, role: str) -> str:
    """Plain-text instruction lines recovered from the split and base64 forms."""
    lines: list[str] = []
    parts: dict[int, dict[int, str]] = {}
    for k, n, fragment in re.findall(rf"{role}\s*\((\d+)/(\d+)\):\s*(.+?)(?:\n|$)", text, re.I):
        parts.setdefault(int(n), {})[int(k)] = fragment.strip()
    for n, got in parts.items():
        if set(got) == set(range(1, n + 1)):
            lines.append(f"{role}: " + " ".join(got[i] for i in range(1, n + 1)))
    for blob in re.findall(rf"{role}-B64:\s*([A-Za-z0-9+/=]+)", text, re.I):
        try:
            lines.append(f"{role}: " + base64.b64decode(blob, validate=True).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError):
            pass
    return "\n".join(lines)


def _only_role_lines(text: str, role: str) -> str:
    """``remember`` instructions addressed to ``role``, as plain ``remember ...`` lines."""
    decoded = text + "\n" + _decoded(text, role)
    return "\n".join(m.group(1) for m in re.finditer(rf"{role}:\s*(remember .+?)(?:\n|$)",
                                                      decoded, re.I))


def injections(text: str, role: str) -> list[tuple[str, str, str | None]]:
    """Find ``ROLE: ask <dest> to <request> [and forward it to <dest>]`` lines."""
    found = []
    pattern = re.compile(rf"{role}:\s*ask (\w+) (?:to |for )?(.+?)(?:\n|$)", re.I)
    for dest, rest in pattern.findall(text + "\n" + _decoded(text, role)):
        forward = None
        match = re.search(r"\s+and forward (?:it|the answer) to (\w+)\.?\s*$", rest, re.I)
        if match:
            forward, rest = match.group(1), rest[: match.start()]
        found.append((dest.casefold(), rest.strip().rstrip("."), forward))
    return found


class DemoAgent(NLIPServer):
    """Shared plumbing: config-driven security, optional client, guarded tools."""

    calls_others = False

    def __init__(self, name: str, settings: DemoSettings, world: World) -> None:
        security = settings.security(name)
        super().__init__(name, security=security)
        self.world = world
        self.entity = name
        self.custody_id = settings.identities.get(name)
        store = custody_store(self.custody_id) if (settings.custody and self.custody_id) else None
        self.guard: CustodyToolGuard | None = settings.guard(name, store)
        self.client: NLIPClient | None = None
        if self.calls_others:
            self.client = NLIPClient(
                settings.endpoints(exclude=name), identity=name, security=security
            )
            if settings.mode == "http":
                reuse_connections(self.client)

    def tool(
        self, name: str, fn: Callable[..., Awaitable[Any]], session: NLIPSession
    ) -> Callable[..., Awaitable[Any]]:
        """Bind a tool to this task, behind the custody check when custody is on."""
        guard = self.guard
        if guard is None:
            return fn

        async def call(**args: Any) -> Any:
            decision = guard.check(session.id, name, args)
            if not decision.allowed:
                # The guard has queued a consent request; the custody SE signs it and
                # carries it back to the user's client. The model only sees this text.
                self.world.tool_blocks.append(f"{self.entity}.{name}")
                return f"{BLOCKED} {decision.reason}"
            result = await fn(**args)
            guard.tag(session.id, name, args, result)
            return result

        return call

    async def send(self, destination: str, text: str, session: NLIPSession) -> str:
        assert self.client is not None
        if destination not in self.client.destinations:
            return f"(no such agent: {destination})"
        try:
            reply = await self.client.send_text(destination, text, scope=session.id)
        except Exception as error:  # a peer's SE blocked us, or a transport error
            return f"(call to {destination} failed: {error})"
        return reply.extract_text(language=None) or ""

    async def send_raw(self, destination: str, text: str, session: NLIPSession) -> NLIPMessage | None:
        assert self.client is not None
        if destination not in self.client.destinations:
            return None
        try:
            return await self.client.send_text(destination, text, scope=session.id)
        except Exception as error:
            return NLIPMessage.text(f"(call to {destination} failed: {error})")

    async def follow(self, role: str, text: str, session: NLIPSession, depth: int = 0) -> list[str]:
        """Worst case: obey every instruction addressed to ``role`` in ``text``."""
        out: list[str] = []
        if depth >= MAX_FOLLOW:
            return out
        for dest, request, forward in injections(text, role):
            answer = await self.send(dest, request, session)
            out.append(f"[{dest}] {answer}")
            if forward:
                out.append(f"[{forward}] {await self.send(forward, answer, session)}")
            out.extend(await self.follow(role, answer, session, depth + 1))
        return out

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> str | NLIPMessage:
        return await self.script(message.extract_text(language=None) or "", session)

    async def script(self, text: str, session: NLIPSession) -> str:
        raise NotImplementedError


REMEMBER = re.compile(r"remember ([\w-]+)\s*=\s*(.+?)\.?\s*(?:\n|$)", re.I)


class Assistant(DemoAgent):
    """Also has a memory that outlives conversations: ``remember`` and ``recall``."""

    calls_others = True

    async def remember(self, key: str, value: str, session: NLIPSession) -> str:
        async def remember(key: str, value: str) -> str:
            self.world.memory[key] = value
            return f"Noted {key}."

        return await self.tool("remember", remember, session)(key=key, value=value)

    async def recall(self, key: str, session: NLIPSession) -> str:
        async def recall(key: str) -> str:
            return self.world.memory.get(key, "")

        return await self.tool("recall", recall, session)(key=key)

    async def follow(self, role: str, text: str, session: NLIPSession, depth: int = 0) -> list[str]:
        out = []
        # Worst case also for memory: obey "ASSISTANT: remember <key> = <value>".
        for key, value in REMEMBER.findall(_only_role_lines(text, role)):
            out.append(await self.remember(key, value, session))
        return out + await super().follow(role, text, session, depth)

    async def check_inbox(self, text: str, session: NLIPSession) -> list[str]:
        """Ask the sandboxed reader for a typed summary instead of reading mail text."""
        reply = await self.send_raw("reader", "summarise my inbox", session)
        if reply is None or not isinstance(reply.content, dict):
            return [reply.extract_text(language=None) if reply else "(reader unavailable)"]
        data = reply.content
        parts = [f"You have {data.get('messages')} messages "
                 f"({data.get('from_known_contacts')} from known contacts). "
                 f"Invoice: {'yes' if data.get('has_invoice') else 'no'}."]
        # Worst case: pass on anything else the reader returned, verbatim.
        known = {"messages", "from_known_contacts", "has_invoice", "urgent", "invoice"}
        parts += [f"Reader also says: {v}" for k, v in data.items() if k not in known]
        invoice = data.get("invoice")
        if "pay any invoice" in text.casefold() and isinstance(invoice, dict):
            parts.append(await self.send(
                "finance", f"pay {invoice['amount']} to account {invoice['account']} "
                           f"for {invoice['payee']}", session))
        return parts

    async def script(self, text: str, session: NLIPSession) -> str:
        parts: list[str] = []
        lowered = text.casefold()
        if "check my inbox" in lowered:
            parts.extend(await self.check_inbox(text, session))
        elif lowered.startswith("remember ") and (m := REMEMBER.match(text)) is not None:
            parts.append(await self.remember(m.group(1), m.group(2), session))
        elif "standing order" in lowered:
            order = await self.recall("standing-order", session)
            if (m := PAY.search(order)) is not None:
                parts.append(await self.send("finance", m.group(0), session))
            else:
                parts.append("You have no standing orders.")
        elif "invoice" in lowered and "inbox" in lowered:
            inbox = await self.send("inbox", "summarise my inbox", session)
            parts.append(inbox)
            for amount, account, payee in INVOICE.findall(inbox):
                parts.append(await self.send(
                    "finance", f"pay {amount} to account {account} for {payee}", session))
        elif "inbox" in lowered:
            parts.append(await self.send("inbox", "summarise my inbox", session))
        elif (m := PAY.search(text)) is not None:
            parts.append(await self.send("finance", m.group(0), session))
        elif (m := SALARY.search(text)) is not None:
            parts.append(await self.send("hr", m.group(0), session))
        elif (m := re.search(r"ask (\w+) (?:for|to) (.+)", text, re.I)) is not None:
            parts.append(await self.send(m.group(1).casefold(), m.group(2), session))
        else:
            parts.append("I can pay bills, look up salaries and read your inbox.")
        # Worst case: obey instructions addressed to the assistant in anything it read.
        for part in list(parts):
            parts.extend(await self.follow("ASSISTANT", part, session))
        return "\n".join(parts)


class Inbox(DemoAgent):
    calls_others = True

    async def script(self, text: str, session: NLIPSession) -> str:
        async def read_inbox() -> list[dict[str, str]]:
            return [mail.to_json() for mail in self.world.mailbox]

        mails = await self.tool("read_inbox", read_inbox, session)()
        if not mails:
            return "Your inbox is empty."
        summary = "\n".join(f"From {m['from']}: {m['subject']}. {m['body']}" for m in mails)
        followed = await self.follow("INBOX", summary, session)
        return "\n".join([summary, *followed])


KNOWN_CONTACTS = {"mum@home.net", "news@acme.example", "hello@gym.example",
                  "office@school.example", "alerts@bank.example", "billing@plumber.example"}


class Reader(DemoAgent):
    """Sandboxed inbox reader: reads mail, calls nobody, answers with typed JSON only.

    Its scripted model is still worst case: it obeys ``READER: note <text>`` by adding
    a free-text ``note`` field. That breaks the schema, so the SE will not endorse the
    reply and the mail senders travel as usual.
    """

    async def script(self, text: str, session: NLIPSession) -> NLIPMessage:
        async def read_inbox() -> list[dict[str, str]]:
            return [mail.to_json() for mail in self.world.mailbox]

        mails = await self.tool("read_inbox", read_inbox, session)()
        bodies = "\n".join(f"{m['subject']}. {m['body']}" for m in mails)
        found = INVOICE.search(bodies)
        summary: dict[str, Any] = {
            "messages": len(mails),
            "from_known_contacts": sum(m["from"] in KNOWN_CONTACTS for m in mails),
            "has_invoice": found is not None,
            "urgent": "urgent" in bodies.casefold(),
            "invoice": ({"payee": found.group(3), "account": found.group(2),
                         "amount": int(found.group(1))} if found else None),
        }
        for note in re.findall(r"READER:\s*note\s+(.+?)(?:\n|$)", bodies, re.I):
            summary["note"] = note
        return NLIPMessage.structured(summary)


class Finance(DemoAgent):

    async def script(self, text: str, session: NLIPSession) -> str:
        m = PAY.search(text)
        if m is None:
            return "Finance can pay: 'pay <amount> to account <account> for <payee>'."

        async def pay(payee: str, account: str, amount: int) -> str:
            self.world.ledger.append(Payment(payee, account, amount))
            return f"Paid {amount} to account {account} ({payee})."

        amount, account, payee = int(m.group(1)), m.group(2), m.group(3) or "unnamed"
        return await self.tool("pay", pay, session)(payee=payee, account=account, amount=amount)


class HR(DemoAgent):

    async def script(self, text: str, session: NLIPSession) -> str:
        m = SALARY.search(text)
        if m is None:
            return "HR answers: 'salary of <employee>'."

        async def get_salary(employee: str) -> str:
            salary = self.world.salaries.get(employee)
            if salary is None:
                return f"No employee named {employee}."
            self.world.salary_reads.append(employee)
            return f"The salary of {employee} is {salary:,}."

        return await self.tool("get_salary", get_salary, session)(employee=m.group(1).casefold())


class Rogue(DemoAgent):
    """A third-party agent that runs no Custody and replies with an injection."""


    async def script(self, text: str, session: NLIPSession) -> str:
        self.world.rogue_received.append(text)
        return self.world.rogue_reply


AGENTS: dict[str, type[DemoAgent]] = {
    "assistant": Assistant,
    "inbox": Inbox,
    "reader": Reader,
    "finance": Finance,
    "hr": HR,
    "rogue": Rogue,
}
