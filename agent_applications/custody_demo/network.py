"""Wire the demo's agents together: in-process (default) or over real HTTP."""

from __future__ import annotations

from collections.abc import Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer
from nlip_sdk.nlip_security_extensions import SecurityBlockedError

from security_extensions.custody.consent import ConsentIssuer
from security_extensions.custody.keys import load_pinned_keys, load_private_key
from security_extensions.custody.request import ConsentDesk, ConsentRequestClaims
from security_extensions.custody.signer import CustodySigner
from security_extensions.custody.token import message_digest
from security_extensions.custody.store import custody_store, reset_custody_stores

from .agents import AGENTS, DemoAgent
from .transport import reuse_connections
from .settings import DemoSettings, key_filename
from .world import World

USER_PRINCIPAL = "user:h:alice"


class DemoNetwork:
    """All five agents plus the user's client, sharing one mock world.

    ``inproc``: every agent is a real NLIPServer in this process and client posts are
    routed straight into ``process_exchange`` (same pipelines, no sockets).
    ``http``: agents run elsewhere (see ``serve.py``) and clients use real HTTP.
    """

    def __init__(self, settings: DemoSettings, world: World) -> None:
        reset_custody_stores()
        self.settings = settings
        self.world = world
        self.servers: dict[str, DemoAgent] = {}
        # Last message each outside client put on the wire, and a post that bypasses
        # that client's own security pipeline (for replay and forgery attacks).
        self.captured: dict[str, tuple[str, NLIPMessage]] = {}
        self.raw_post: dict[str, Callable] = {}
        # The user's consent desk: verifies requests against the participating
        # agents' pinned keys before anything is shown to the user.
        self.desk = ConsentDesk(load_pinned_keys(
            {i: k for i, k in settings.public_keys.items() if i != settings.user_identity}))
        self.shown_requests: list[ConsentRequestClaims] = []
        self.rejected_requests: list[str] = []
        if settings.mode == "inproc":
            for name, cls in AGENTS.items():
                self.servers[name] = cls(name, settings, world)
                if self.servers[name].client is not None:
                    self._route(self.servers[name].client)
        self.user = self._client("user")
        self.rogue = self._client("rogue")

    def _client(self, name: str) -> NLIPClient:
        client = NLIPClient(
            self.settings.endpoints(exclude=name),
            identity=name,
            security=self.settings.security(name),
        )
        if self.settings.mode == "inproc":
            self._route(client)
        else:
            reuse_connections(client)
        inner = client._post
        self.raw_post[name] = inner

        async def recording_post(destination: str, message: NLIPMessage) -> httpx.Response:
            self.captured[name] = (destination, message.model_copy(deep=True))
            return await inner(destination, message)

        client._post = recording_post  # type: ignore[method-assign]
        return client

    def _route(self, client: NLIPClient) -> None:
        servers: dict[str, NLIPServer] = self.servers  # type: ignore[assignment]

        async def post(destination: str, message: NLIPMessage) -> httpx.Response:
            request = httpx.Request("POST", client.endpoints[destination])
            try:
                reply = await servers[destination].process_exchange(message)
            except SecurityBlockedError as error:
                return httpx.Response(403, json={"detail": str(error)}, request=request)
            return httpx.Response(200, json=reply.to_dict(), request=request)

        client._post = post  # type: ignore[method-assign]

    # ------------------------------------------------------------ user side

    async def ask(self, text: str) -> str:
        """The user types ``text`` to their assistant (one conversation per network)."""
        try:
            reply = await self.user.send_text("assistant", text)
        except httpx.HTTPStatusError as error:
            return f"(assistant refused: {error.response.text})"
        return reply.extract_text(language=None) or ""

    async def rogue_says(self, destination: str, text: str) -> str:
        """The rogue agent calls another agent directly."""
        try:
            reply = await self.rogue.send_text(destination, text)
        except httpx.HTTPStatusError as error:
            return f"(refused: {error.response.text})"
        return reply.extract_text(language=None) or ""

    async def replay_user_request(self) -> str:
        """Attack: re-send the user's last wire message, byte for byte."""
        destination, message = self.captured["user"]
        response = await self.raw_post["user"](destination, message)
        if response.status_code != 200:
            return f"(replay refused: {response.status_code})"
        return NLIPMessage.model_validate(response.json()).extract_text(language=None) or ""

    async def rogue_forged(self, destination: str, text: str) -> str:
        """Attack: the rogue claims to be the assistant with a self-signed custody token."""
        claimed = self.settings.identities["assistant"]
        forger = CustodySigner(claimed, Ed25519PrivateKey.generate())
        message = NLIPMessage.text(text)
        aud = self.settings.identities.get(destination, f"agent:x/{destination}")
        message.add_token(
            forger.sign(aud, message_digest(message), [USER_PRINCIPAL, self.settings.user_identity]),
            forger.subformat,
        )
        try:
            reply = await self.rogue.send(destination, message)
        except httpx.HTTPStatusError as error:
            return f"(refused: {error.response.status_code})"
        return reply.extract_text(language=None) or ""

    def pending_requests(self) -> list[ConsentRequestClaims]:
        """Consent requests that reached the user's client and verify there.

        They arrived as signed ``consentreq_*`` token parts on the assistant's reply
        and were collected by the user client's custody SE. Requests that fail
        verification (forged, tampered, expired) are dropped here and never shown.
        """
        if not self.settings.consent:
            return []
        store = custody_store(self.settings.user_identity)
        shown, self.rejected_requests = self.desk.pending(store.take_request_tokens(None))
        self.shown_requests.extend(shown)
        return shown

    def approve_pending(self, wants: Callable[[str, dict], bool] = lambda tool, args: True) -> int:
        """Simulated user: approve the shown requests ``wants`` accepts, once each.

        The approval is built from the *signed* request's tool and arguments, never
        from anything a model wrote. The user's client signs it; the custody SE carries
        it down the chain on the retry. Returns the number of approvals.
        """
        if not self.settings.consent:
            return 0
        key = load_private_key(self.settings.keys_dir / key_filename(self.settings.user_identity))
        issuer = ConsentIssuer(self.settings.user_identity, USER_PRINCIPAL, key)
        store = custody_store(self.settings.user_identity)
        self.pending_requests()
        chosen = [r for r in self.shown_requests if wants(r.tool, r.args)]
        for request in chosen:
            store.add_consent(None, ConsentDesk.approve(request, issuer))
        self.shown_requests.clear()
        return len(chosen)
