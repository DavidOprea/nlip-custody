"""The Custody NLIP security extension (Type-2: agent to agent).

It keeps, outside the model, the set of principals whose content shaped each task,
and carries that set on every NLIP message as a signed, single-use custody token.

========================  =====================================================
point                     what it does
========================  =====================================================
server ingress            verify the caller's token, merge ``iss`` + principals
                          into the task (``unknown`` if no token), strip custody
                          tokens so the handler/model never sees them
server egress             sign the task's set into a reply token for the caller
client egress             sign the task's set into a token for the destination
client ingress            verify the reply token, merge it into the calling task,
                          strip all custody tokens (incl. echoes of our own) so
                          the SDK never stores or re-sends them
========================  =====================================================

The decision on sensitive actions happens later, in the tool hook (Type-3), using
the same :func:`custody_store`.

Must be the LAST extension in every egress pipeline: a later REPLACE would change
the message the token's digest is bound to.

Example ``config.toml``::

    [security_extensions.custody_assistant]
    entrypoint = "security_extensions.custody.extension:CustodyExtension"
    [security_extensions.custody_assistant.options]
    identity = "agent:acme/assistant"
    signer = "tcp:127.0.0.1:47011"           # separate signer process
    peers = { finance = "agent:fin/finance" }  # NLIP entity name -> identity
    pinned_keys = { "agent:fin/finance" = "<b64url>", "agent:acme/user-client" = "<b64url>" }
    log_path = "logs/custody_assistant.jsonl"
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable, Collection, Mapping
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nlip_sdk import NLIPMessage
from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityDecision,
    SecurityEvent,
    SecurityExtension,
)

from .consent import consent_subformat, decode_consent_unverified, is_consent_subformat
from .keys import load_private_key, load_public_key
from .replay import ReplayCache
from .signer import CustodySigner, RemoteSigner, Signer, SignerError
from .store import UNKNOWN, CustodyStore, DecisionLog, custody_store
from .token import (
    CustodyClaims,
    CustodyTokenError,
    CustodyVerifier,
    agent_org,
    is_custody_subformat,
    message_digest,
    subformat_for,
    validate_principal,
)


def _is_ours(subformat: str) -> bool:
    return is_custody_subformat(subformat) or is_consent_subformat(subformat)


def _has_custody_token(message: NLIPMessage) -> bool:
    return any(_is_ours(t.subformat) for t in message.token_submessages())


def _strip(message: NLIPMessage) -> NLIPMessage:
    """Remove custody and consent token parts (they never reach models or storage)."""
    cleaned = message.model_copy(deep=True)
    if cleaned.submessages:
        kept = [
            p for p in cleaned.submessages
            if not (p.format == "token" and _is_ours(p.subformat))
        ]
        cleaned.submessages = kept or None
    return cleaned


def _consent_tokens(message: NLIPMessage) -> list[str]:
    return [
        str(t.content)
        for t in message.token_submessages()
        if is_consent_subformat(t.subformat)
    ]


class CustodyExtension(SecurityExtension):
    def __init__(
        self,
        identity: str,
        *,
        signer: Signer | str | None = None,
        key_file: str | None = None,
        authkey_env: str = "CUSTODY_SIGNER_AUTHKEY",
        pinned_keys: Mapping[str, str | Ed25519PublicKey] | None = None,
        peers: Mapping[str, str] | None = None,
        origin_principals: Collection[str] = (),
        on_invalid_token: Literal["block", "unknown"] = "block",
        ttl: int = 60,
        log_path: str | None = None,
        store: CustodyStore | None = None,
        replay_cache: ReplayCache | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        agent_org(identity)
        if (signer is None) == (key_file is None):
            raise ValueError("Configure exactly one of signer (process) or key_file.")
        if on_invalid_token not in {"block", "unknown"}:
            raise ValueError("on_invalid_token must be 'block' or 'unknown'.")
        self.identity = identity
        self.subformat = subformat_for(identity)

        self._signer: Signer | None
        self._signer_address: str | None = None
        self._authkey_env = authkey_env
        if key_file is not None:
            # In-process key: for unit tests and the scripted demo only. The key is
            # then readable by the agent process, which the threat model forbids.
            self._signer = CustodySigner(
                identity, load_private_key(key_file), ttl=ttl, clock=clock
            )
        elif isinstance(signer, str):
            self._signer = None  # connect lazily, so agents may start before signers
            self._signer_address = signer
        else:
            assert signer is not None
            if signer.identity != identity:
                raise ValueError("Signer identity does not match the extension.")
            self._signer = signer

        keys = {
            name: key if isinstance(key, Ed25519PublicKey) else load_public_key(key)
            for name, key in (pinned_keys or {}).items()
        }
        self._verifier = CustodyVerifier(
            identity,
            keys,
            replay_cache if replay_cache is not None else ReplayCache(clock=clock),
            clock=clock,
        )
        self._peers = {name.strip().casefold(): ident for name, ident in (peers or {}).items()}
        for ident in self._peers.values():
            agent_org(ident)
        self._origin = frozenset(validate_principal(p) for p in origin_principals)
        self._on_invalid = on_invalid_token
        self.store = store if store is not None else custody_store(identity)
        self.log = DecisionLog(log_path)

    # ------------------------------------------------------------------ helpers

    def _get_signer(self) -> Signer:
        if self._signer is None:
            authkey = os.environ.get(self._authkey_env, "").encode("utf-8")
            if not authkey:
                raise SignerError(f"Set {self._authkey_env} to reach the signer.")
            assert self._signer_address is not None
            self._signer = RemoteSigner(
                self._signer_address, authkey, identity=self.identity
            )
        return self._signer

    async def _sign(self, message: NLIPMessage, aud: str, principals: Collection[str]) -> NLIPMessage:
        """Return ``message`` without stray custody tokens, plus one fresh token."""
        out = _strip(message)
        signer = self._get_signer()
        args = (aud, message_digest(out), sorted(principals))
        if isinstance(signer, RemoteSigner):
            token = await asyncio.to_thread(signer.sign, *args)
        else:
            token = signer.sign(*args)
        out.add_token(token, self.subformat)
        return out

    def _verify(
        self, event: SecurityEvent, expected_issuer: str | None
    ) -> tuple[CustodyClaims | None, str | None]:
        """Return (claims, error). ``(None, None)`` means no token for us."""
        try:
            claims = self._verifier.select(event.message)
        except CustodyTokenError as error:
            return None, str(error)
        if claims is not None and expected_issuer and claims.iss != expected_issuer:
            return None, f"Reply signed by {claims.iss}, expected {expected_issuer}."
        return claims, None

    def _record(self, event: SecurityEvent, action: str, **fields: object) -> None:
        self.log.write(
            identity=self.identity,
            component=event.component,
            point=event.point.value,
            scope=event.scope,
            peer=event.session.peer,
            action=action,
            **fields,
        )

    # --------------------------------------------------------------- evaluate

    async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        inbound = event.point is EnforcementPoint.INGRESS
        if event.component == "server":
            return await (self._server_ingress if inbound else self._server_egress)(event)
        return await (self._client_ingress if inbound else self._client_egress)(event)

    async def _merge_inbound(
        self, event: SecurityEvent, expected_issuer: str | None
    ) -> tuple[SecurityDecision | None, CustodyClaims | None]:
        claims, error = self._verify(event, expected_issuer)
        if error is not None:
            self._record(event, "reject", reason=error)
            if self._on_invalid == "block":
                return SecurityDecision.block(f"custody: {error}"), None
        added = {claims.iss, *claims.principals} if claims else {UNKNOWN}
        total = self.store.add(event.scope, added)
        self._record(
            event,
            "merge",
            iss=claims.iss if claims else None,
            added=sorted(added),
            principals=sorted(total),
            reason=error,
        )
        return None, claims

    async def _server_ingress(self, event: SecurityEvent) -> SecurityDecision:
        blocked, claims = await self._merge_inbound(event, expected_issuer=None)
        if blocked is not None:
            return blocked
        for token in _consent_tokens(event.message):
            # Opaque here; the tool guard verifies audience, call and signature.
            self.store.add_consent(event.scope, token)
        caller = claims.iss if claims else None
        self.store.set_caller(event.scope, caller)
        if caller is not None and event.session.peer is None:
            # The framework creates server sessions with peer=None; a verified
            # token is the first trustworthy caller identity this session has.
            event.session.peer = caller
        if _has_custody_token(event.message):
            return SecurityDecision.replace(_strip(event.message), "custody tokens removed")
        return SecurityDecision.allow()

    async def _server_egress(self, event: SecurityEvent) -> SecurityDecision:
        caller = self.store.caller(event.scope)
        if caller is None:
            self._record(event, "unsigned", reason="caller sent no custody token")
            return SecurityDecision.allow()
        principals = self.store.principals(event.scope)
        signed = await self._sign(event.message, caller, principals)
        self._record(event, "sign", aud=caller, principals=sorted(principals))
        return SecurityDecision.replace(signed, "custody token attached")

    async def _client_egress(self, event: SecurityEvent) -> SecurityDecision:
        destination = (event.session.peer or "").casefold()
        aud = self._peers.get(destination)
        if aud is None:
            self._record(event, "unsigned", reason="destination runs no custody")
            return SecurityDecision.allow()
        if event.scope is None and self._origin:
            # An originating client (e.g. the user's chat client): the human
            # authors each message, so only the configured origin principals apply.
            principals = self._origin
        else:
            principals = self.store.principals(event.scope)
        signed = await self._sign(event.message, aud, principals)
        consents = self.store.consents(event.scope)
        for token in consents:
            try:
                issuer = decode_consent_unverified(token)[0].iss
            except CustodyTokenError:
                continue
            signed.add_token(token, consent_subformat(issuer))
        self._record(
            event, "sign", aud=aud, principals=sorted(principals), consents=len(consents)
        )
        return SecurityDecision.replace(signed, "custody token attached")

    async def _client_ingress(self, event: SecurityEvent) -> SecurityDecision:
        expected = self._peers.get((event.session.peer or "").casefold())
        blocked, _ = await self._merge_inbound(event, expected_issuer=expected)
        if blocked is not None:
            return blocked
        if _has_custody_token(event.message):
            return SecurityDecision.replace(_strip(event.message), "custody tokens removed")
        return SecurityDecision.allow()
