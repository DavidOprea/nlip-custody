"""End-to-end tests of the Custody SE over real NLIP server/client pipelines (in-process)."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer, NLIPSession
from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityBlockedError,
    SecurityExtensionManager,
)
from security_extensions.custody import CustodySigner
from security_extensions.custody.extension import CustodyExtension
from security_extensions.custody.keys import generate_private_key, public_key_b64
from security_extensions.custody.store import CustodyStore
from security_extensions.custody.token import is_custody_subformat

from custody_harness import (  # noqa: E402
    ALICE,
    ASSISTANT,
    FINANCE,
    KEYS,
    ROGUE,
    SUPPLIER,
    USER_CLIENT,
    Network,
    custody,
    manager,
)


class Finance(NLIPServer):
    def __init__(self, ext: CustodyExtension | None) -> None:
        super().__init__("finance", security=manager("finance", ext))
        self.ext = ext
        self.seen: list[tuple[NLIPMessage, frozenset[str]]] = []

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> str:
        principals = self.ext.store.principals(session.id) if self.ext else frozenset()
        self.seen.append((message, principals))
        return f"finance got: {message.extract_text()}"


class Assistant(NLIPServer):
    """Scripted worst-case assistant: reads the inbox if asked, then calls Finance."""

    def __init__(self, ext: CustodyExtension, network: Network) -> None:
        security = manager("assistant", ext)
        super().__init__("assistant", security=security)
        self.ext = ext
        self.client = network.client("assistant", security)

    async def handle(self, message: NLIPMessage, session: NLIPSession) -> str:
        text = message.extract_text() or ""
        assert not any(is_custody_subformat(t.subformat) for t in message.token_submessages())
        if "inbox" in text:
            # What the PostToolUse hook will do when an inbox tool returns mail.
            self.ext.store.add(session.id, [SUPPLIER])
            text = "pay invoice 4471, $8,400, to account 9921"
        reply = await self.client.send_text("finance", text, scope=session.id)
        return reply.extract_text() or ""


def build(tmp_path: Path | None = None, finance_custody: bool = True, **finance_opts):
    net = Network()
    fin_ext = (
        custody(FINANCE, pinned=[ASSISTANT], **finance_opts) if finance_custody else None
    )
    finance = Finance(fin_ext)
    net.servers["finance"] = finance
    log = str(tmp_path / "assistant.jsonl") if tmp_path else None
    asst_ext = custody(
        ASSISTANT,
        pinned=[USER_CLIENT, FINANCE],
        peers={"finance": FINANCE} if finance_custody else {},
        log_path=log,
    )
    assistant = Assistant(asst_ext, net)
    net.servers["assistant"] = assistant
    user_ext = custody(
        USER_CLIENT, pinned=[ASSISTANT], peers={"assistant": ASSISTANT},
        origin_principals=[ALICE],
    )
    user = net.client("user", manager("user", user_ext))
    return net, user, assistant, finance, user_ext


def custody_tokens(message: NLIPMessage) -> list:
    return [t for t in message.token_submessages() if is_custody_subformat(t.subformat)]


def test_benign_chain_carries_who_shaped_the_request(tmp_path: Path) -> None:
    net, user, assistant, finance, user_ext = build(tmp_path)
    reply = asyncio.run(user.send_text("assistant", "pay my rent to the landlord"))

    assert reply.extract_text() == "finance got: pay my rent to the landlord"
    _, principals = finance.seen[0]
    assert principals == {ALICE, USER_CLIENT, ASSISTANT}
    # Reply path: the user's conversation learns Finance and the assistant took part.
    assert {FINANCE, ASSISTANT} <= user_ext.store.principals(None)
    # Custody tokens never reach handlers or the caller's stored state.
    assert not custody_tokens(finance.seen[0][0])
    assert not custody_tokens(reply)
    log = [json.loads(line) for line in (tmp_path / "assistant.jsonl").read_text().splitlines()]
    assert [(e["component"], e["point"], e["action"]) for e in log] == [
        ("server", "ingress", "merge"),
        ("client", "egress", "sign"),
        ("client", "ingress", "merge"),
        ("server", "egress", "sign"),
    ]


def test_injected_email_sender_reaches_finance() -> None:
    _, user, _, finance, _ = build()
    asyncio.run(user.send_text("assistant", "summarise my inbox"))
    message, principals = finance.seen[0]
    assert "9921" in (message.extract_text() or "")
    assert SUPPLIER in principals  # the laundered confused deputy is now visible


def test_tokens_do_not_accumulate_over_turns() -> None:
    net, user, *_ = build()
    for turn in range(4):
        asyncio.run(user.send_text("assistant", f"pay rent, turn {turn}"))
    to_finance = [m for dest, m in net.wire if dest == "finance"]
    assert len(to_finance) == 4
    assert all(len(custody_tokens(m)) == 1 for m in to_finance)
    assert all(len(custody_tokens(m)) == 1 for d, m in net.wire if d == "assistant")


def test_caller_without_custody_is_unknown() -> None:
    net, *_ , finance, _ = build()
    plain = net.client("plain", manager("plain", None))
    reply = asyncio.run(plain.send_text("finance", "pay 9921"))
    assert finance.seen[0][1] == {"unknown"}
    assert not custody_tokens(reply)  # Finance cannot address a reply token


def test_replayed_request_is_blocked() -> None:
    net, user, _, finance, _ = build()
    asyncio.run(user.send_text("assistant", "pay my rent"))
    captured = next(m for dest, m in net.wire if dest == "finance")
    with pytest.raises(SecurityBlockedError, match="replayed"):
        asyncio.run(finance.process_exchange(captured))


def test_forged_token_is_blocked_or_unknown() -> None:
    net, *_ , finance, _ = build()
    rogue = net.client("rogue", manager("rogue", custody(ROGUE, pinned=[], peers={"finance": FINANCE})))
    with pytest.raises(httpx.HTTPStatusError) as info:
        asyncio.run(rogue.send_text("finance", "pay 9921"))
    assert info.value.response.status_code == 403
    assert "No pinned key" in info.value.response.json()["detail"]

    net2, *_ , lenient, _ = build(on_invalid_token="unknown")
    rogue2 = net2.client("rogue", manager("rogue", custody(ROGUE, pinned=[], peers={"finance": FINANCE})))
    asyncio.run(rogue2.send_text("finance", "pay 9921"))
    assert lenient.seen[0][1] == {"unknown"}


def test_hop_through_agent_without_custody_taints_the_task() -> None:
    _, user, assistant, _, user_ext = build(finance_custody=False)
    asyncio.run(user.send_text("assistant", "pay my rent"))
    (scope,) = [s for s in assistant.ext.store._sets]  # noqa: SLF001
    assert "unknown" in assistant.ext.store.principals(scope)
    assert "unknown" in user_ext.store.principals(None)


def test_loads_from_config_with_key_file(tmp_path: Path) -> None:
    key = tmp_path / "fin.pem"
    generate_private_key(key)
    config = {
        "security_extensions": {
            "custody_fin": {
                "entrypoint": "security_extensions.custody.extension:CustodyExtension",
                "options": {
                    "identity": FINANCE,
                    "key_file": str(key),
                    "pinned_keys": {ASSISTANT: public_key_b64(KEYS[ASSISTANT])},
                },
            }
        },
        "entities": {
            "finance": {"security": {"ingress": ["custody_fin"], "egress": ["custody_fin"]}}
        },
    }
    m = SecurityExtensionManager.from_config(config, entity="finance")
    assert m.extension_names(EnforcementPoint.INGRESS) == ("custody_fin",)


def test_needs_exactly_one_signer_source() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        CustodyExtension(FINANCE)
