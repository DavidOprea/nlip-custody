"""SecurityEvent.scope links outbound client traffic to the inbound session that caused it."""

import asyncio

import httpx

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer, NLIPSession
from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityDecision,
    SecurityEvent,
    SecurityExtension,
    SecurityExtensionManager,
)


class Record(SecurityExtension):
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        self.events.append(event)
        return SecurityDecision.allow()


def _manager(entity: str, extension: SecurityExtension) -> SecurityExtensionManager:
    manager = SecurityExtensionManager(entity)
    manager.register("ext", extension, list(EnforcementPoint))
    return manager


def _client_with_fake_peer(
    security: SecurityExtensionManager, extra_token: tuple[str, str] | None = None
) -> NLIPClient:
    client = NLIPClient(
        {"peer": "http://peer.test/nlip"}, identity="client", security=security
    )

    async def fake_post(destination: str, message: NLIPMessage) -> httpx.Response:
        response = NLIPMessage.text("ok")
        response.echo_tokens_from(message)
        if extra_token is not None:
            response.add_token(*extra_token)
        return httpx.Response(
            200,
            json=response.to_dict(),
            request=httpx.Request("POST", client.endpoints[destination]),
        )

    client._post = fake_post  # type: ignore[method-assign]
    return client


def test_client_egress_and_ingress_carry_scope() -> None:
    record = Record()
    client = _client_with_fake_peer(_manager("client", record))

    asyncio.run(client.send_text("peer", "hi", scope="inbound-1"))
    asyncio.run(client.send_text("peer", "hi", scope="inbound-2"))
    asyncio.run(client.send_text("peer", "hi"))

    assert [(e.point.value, e.scope) for e in record.events] == [
        ("egress", "inbound-1"),
        ("ingress", "inbound-1"),
        ("egress", "inbound-2"),
        ("ingress", "inbound-2"),
        ("egress", None),
        ("ingress", None),
    ]
    assert client.session("peer", scope="inbound-1").scope == "inbound-1"
    assert client.create_session("peer").scope is None


def test_server_events_carry_server_session_id_as_scope() -> None:
    record = Record()

    class Echo(NLIPServer):
        async def handle(self, message: NLIPMessage, session: NLIPSession) -> str:
            return "ok"

    server = Echo("server", security=_manager("server", record))
    response = asyncio.run(server.process_exchange(NLIPMessage.text("hi")))
    session_id = response.extract_token("conversation_server")

    assert session_id
    assert [(e.point.value, e.scope) for e in record.events] == [
        ("ingress", session_id),
        ("egress", session_id),
    ]


def test_scope_defaults_to_none_when_enforce_is_called_directly() -> None:
    record = Record()
    manager = _manager("x", record)
    asyncio.run(
        manager.enforce_ingress(
            NLIPMessage.text("hi"), NLIPSession("s"), component="server"
        )
    )
    assert record.events[0].scope is None


def test_client_ingress_replace_strips_tokens_before_they_are_stored() -> None:
    """Custody relies on this: echoed custody tokens must not be stored and re-sent."""

    class StripCustody(SecurityExtension):
        async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
            if event.point is not EnforcementPoint.INGRESS:
                return SecurityDecision.allow()
            cleaned = event.message.model_copy(deep=True)
            cleaned.submessages = [
                part
                for part in cleaned.submessages or []
                if not (
                    part.format == "token"
                    and part.subformat.casefold().startswith("custody_")
                )
            ]
            return SecurityDecision.replace(cleaned)

    record = Record()
    manager = SecurityExtensionManager("client")
    manager.register("strip", StripCustody(), list(EnforcementPoint))
    manager.register("record", record, [EnforcementPoint.EGRESS])
    client = _client_with_fake_peer(manager, extra_token=("signed", "custody_peer"))

    asyncio.run(client.send_text("peer", "first", scope="s"))
    asyncio.run(client.send_text("peer", "second", scope="s"))

    second_egress = record.events[1].message
    assert second_egress.extract_token("custody_peer") is None
    assert second_egress.extract_token("conversation_client") is not None
