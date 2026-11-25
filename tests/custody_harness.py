"""Shared in-process NLIP network for custody tests (no HTTP, real pipelines)."""

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer
from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityBlockedError,
    SecurityExtensionManager,
)
from security_extensions.custody import CustodySigner
from security_extensions.custody.extension import CustodyExtension
from security_extensions.custody.store import CustodyStore

USER_CLIENT = "agent:acme/user-client"
ASSISTANT = "agent:acme/assistant"
FINANCE = "agent:fin/finance"
ROGUE = "agent:evil/rogue"
ALICE = "user:h:alice"
SUPPLIER = "external:h:supp1ier"

KEYS = {name: Ed25519PrivateKey.generate() for name in (USER_CLIENT, ASSISTANT, FINANCE, ROGUE)}


def custody(identity: str, *, pinned: list[str], peers=None, **options) -> CustodyExtension:
    return CustodyExtension(
        identity,
        signer=CustodySigner(identity, KEYS[identity]),
        pinned_keys={name: KEYS[name].public_key() for name in pinned},
        peers=peers or {},
        store=CustodyStore(),
        **options,
    )


def manager(entity: str, extension: CustodyExtension | None) -> SecurityExtensionManager:
    m = SecurityExtensionManager(entity)
    if extension is not None:
        m.register("custody", extension, list(EnforcementPoint))
    return m


class Network:
    """Routes NLIPClient posts straight into NLIPServer.process_exchange."""

    def __init__(self) -> None:
        self.servers: dict[str, NLIPServer] = {}
        self.wire: list[tuple[str, NLIPMessage]] = []

    def client(self, identity: str, security: SecurityExtensionManager) -> NLIPClient:
        client = NLIPClient(
            {name: f"http://{name}.test/nlip" for name in self.servers},
            identity=identity,
            security=security,
        )

        async def post(destination: str, message: NLIPMessage) -> httpx.Response:
            self.wire.append((destination, message.model_copy(deep=True)))
            request = httpx.Request("POST", client.endpoints[destination])
            try:
                reply = await self.servers[destination].process_exchange(message)
            except SecurityBlockedError as error:
                return httpx.Response(403, json={"detail": str(error)}, request=request)
            return httpx.Response(200, json=reply.to_dict(), request=request)

        client._post = post  # type: ignore[method-assign]
        return client
