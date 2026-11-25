"""Wire the demo's agents together: in-process (default) or over real HTTP."""

from __future__ import annotations

import httpx

from nlip_sdk import NLIPClient, NLIPMessage, NLIPServer
from nlip_sdk.nlip_security_extensions import SecurityBlockedError

from security_extensions.custody.consent import ConsentIssuer
from security_extensions.custody.keys import load_private_key
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

    def approve_pending(self) -> int:
        """Simulated user: approve every pending consent request, once each.

        The user's own client signs each approval; the custody SE carries it down
        the chain on the retry. Returns the number of approvals.
        """
        if not self.settings.custody:
            return 0
        key = load_private_key(self.settings.keys_dir / key_filename(self.settings.user_identity))
        issuer = ConsentIssuer(self.settings.user_identity, USER_PRINCIPAL, key)
        store = custody_store(self.settings.user_identity)
        requests = list(self.world.consent_requests)
        for request in requests:
            store.add_consent(None, issuer.approve(request.agent, request.tool, request.args))
        self.world.consent_requests.clear()
        return len(requests)
