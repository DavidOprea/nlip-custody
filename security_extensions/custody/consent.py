"""One-time consent tokens: a user's signed approval of one exact tool call.

The framework has no "ask the user" action and NLIP calls time out after 120 s, so
consent is asynchronous: the tool call is blocked, the user approves through their
own (Type-1) client, the client mints a consent token, and the task is retried. The
custody SE carries consent tokens down the chain (``consent_<org>`` token parts),
and the receiving agent's tool guard accepts exactly that call, once.

Wire form: ``<b64url(claims)>.<b64url(ed25519 sig over CONSENT_PREFIX + claims)>``.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .replay import ReplayCache
from .token import (
    NONCE_BYTES,
    CustodyTokenError,
    agent_org,
    b64url_decode,
    b64url_encode,
    validate_principal,
)

CONSENT_PREFIX = b"nlip-consent-v1."
CONSENT_SUBFORMAT_PREFIX = "consent_"
_KEYS = {"v", "typ", "iss", "principal", "aud", "tool", "args_digest", "nonce", "iat", "exp"}


def args_digest(args: Mapping[str, Any]) -> str:
    """Stable digest of a tool call's arguments (canonical JSON)."""
    body = json.dumps(
        dict(args), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def consent_subformat(issuer: str) -> str:
    return f"{CONSENT_SUBFORMAT_PREFIX}{agent_org(issuer)}"


def is_consent_subformat(subformat: str) -> bool:
    return subformat.casefold().startswith(CONSENT_SUBFORMAT_PREFIX)


@dataclass(frozen=True, slots=True)
class ConsentClaims:
    iss: str        # the approving client, e.g. agent:acme/user-client
    principal: str  # the human who approved, e.g. user:h:...
    aud: str        # the agent that will run the tool
    tool: str
    args_digest: str
    nonce: str
    iat: int
    exp: int
    v: int = 1
    typ: str = "consent"

    def to_json(self) -> dict[str, object]:
        return {k: getattr(self, k) for k in sorted(_KEYS)}

    @classmethod
    def from_json(cls, value: object) -> "ConsentClaims":
        if not isinstance(value, dict) or set(value) != _KEYS:
            raise CustodyTokenError("Consent claims have the wrong fields.")
        if value["v"] != 1 or value["typ"] != "consent":
            raise CustodyTokenError("Unsupported consent token.")
        for key in ("iat", "exp"):
            if type(value[key]) is not int:
                raise CustodyTokenError(f"{key} must be an integer.")
        for key in _KEYS - {"v", "iat", "exp"}:
            if not isinstance(value[key], str):
                raise CustodyTokenError(f"{key} must be a string.")
        claims = cls(**{k: value[k] for k in _KEYS})
        agent_org(claims.iss)
        agent_org(claims.aud)
        validate_principal(claims.principal)
        return claims


def _encode(claims: ConsentClaims, key: Ed25519PrivateKey) -> str:
    body = json.dumps(claims.to_json(), sort_keys=True, separators=(",", ":"))
    claims_b64 = b64url_encode(body.encode("utf-8"))
    return f"{claims_b64}.{b64url_encode(key.sign(CONSENT_PREFIX + claims_b64.encode()))}"


def decode_consent_unverified(content: object) -> tuple[ConsentClaims, str, bytes]:
    if not isinstance(content, str) or content.count(".") != 1 or len(content) > 8192:
        raise CustodyTokenError("Malformed consent token.")
    claims_b64, sig_b64 = content.split(".")
    try:
        raw = json.loads(b64url_decode(claims_b64))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CustodyTokenError("Consent claims are not JSON.") from error
    return ConsentClaims.from_json(raw), claims_b64, b64url_decode(sig_b64)


class ConsentIssuer:
    """Lives in the user's own client. Mints one approval for one exact call."""

    def __init__(
        self,
        identity: str,
        principal: str,
        private_key: Ed25519PrivateKey,
        *,
        ttl: int = 600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        agent_org(identity)
        self.identity = identity
        self.principal = validate_principal(principal)
        self.subformat = consent_subformat(identity)
        self._key = private_key
        self._ttl = ttl
        self._clock = clock

    def approve(self, aud: str, tool: str, args: Mapping[str, Any]) -> str:
        now = int(self._clock())
        claims = ConsentClaims(
            iss=self.identity,
            principal=self.principal,
            aud=aud,
            tool=tool,
            args_digest=args_digest(args),
            nonce=b64url_encode(secrets.token_bytes(NONCE_BYTES)),
            iat=now,
            exp=now + self._ttl,
        )
        return _encode(claims, self._key)


class ConsentVerifier:
    """Accepts a consent token for exactly (self, tool, args), once."""

    def __init__(
        self,
        local_identity: str,
        approvers: Mapping[str, Ed25519PublicKey],
        replay_cache: ReplayCache,
        *,
        clock_skew: int = 30,
        max_lifetime: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        agent_org(local_identity)
        self.local_identity = local_identity
        self._approvers = dict(approvers)
        self._replay = replay_cache
        self._skew = clock_skew
        self._max_lifetime = max_lifetime
        self._clock = clock

    def matches(self, content: object, tool: str, args: Mapping[str, Any]) -> ConsentClaims:
        """Verify and consume; raises :class:`CustodyTokenError` if not valid for this call."""
        claims, claims_b64, sig = decode_consent_unverified(content)
        if claims.aud != self.local_identity:
            raise CustodyTokenError("Consent is for another agent.")
        if claims.tool != tool or claims.args_digest != args_digest(args):
            raise CustodyTokenError("Consent is for a different call.")
        key = self._approvers.get(claims.iss)
        if key is None:
            raise CustodyTokenError(f"{claims.iss} may not grant consent.")
        try:
            key.verify(sig, CONSENT_PREFIX + claims_b64.encode("ascii"))
        except InvalidSignature as error:
            raise CustodyTokenError("Bad consent signature.") from error
        now = int(self._clock())
        if claims.iat > now + self._skew:
            raise CustodyTokenError("Consent issued in the future.")
        if claims.exp <= now - self._skew:
            raise CustodyTokenError("Consent expired.")
        if claims.exp - claims.iat > self._max_lifetime:
            raise CustodyTokenError("Consent lifetime too long.")
        if not self._replay.check_and_add(claims.iss, claims.nonce, claims.exp):
            raise CustodyTokenError("Consent already used.")
        return claims
