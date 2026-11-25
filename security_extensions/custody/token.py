"""Custody tokens: signed, single-use, audience-bound principal sets on NLIP messages.

Wire form (an NLIP token submessage)::

    format="token", subformat="custody_<org>",
    content="<b64url(claims JSON)>.<b64url(ed25519 signature)>"

The signature covers ``SIGNING_PREFIX + b64url(claims)``. The claims bind the token to
one audience, one nonce, a short validity window, and a digest of the message's
non-token parts, so the token cannot be moved to another message, another receiver,
or replayed. Other tokens on the message are never covered (they are echoed and
re-attached by the transport).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from nlip_sdk import AllowedFormat, NLIPMessage

from .replay import ReplayCache

VERSION = 1
SUBFORMAT_PREFIX = "custody_"
SIGNING_PREFIX = b"nlip-custody-v1."
NONCE_BYTES = 16

_AGENT = re.compile(r"^agent:([a-z0-9][a-z0-9_.-]*)/([a-z0-9][a-z0-9_.-]*)$")
_PRINCIPAL = re.compile(
    r"^(?:unknown|user:[^\s]{1,200}|external:[^\s]{1,200}"
    r"|agent:[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.*-]*)$"
)
_CLAIM_KEYS = {"v", "iss", "aud", "nonce", "iat", "exp", "msg_digest", "principals"}


class CustodyTokenError(ValueError):
    """A custody token is malformed, unverifiable, stale, replayed, or misdirected."""


# ---------------------------------------------------------------------------
# Identities and principals
# ---------------------------------------------------------------------------


def agent_org(identity: str) -> str:
    """Return ``org`` from ``agent:<org>/<name>``."""
    match = _AGENT.match(identity)
    if match is None:
        raise CustodyTokenError(f"Not an agent identity: {identity!r}.")
    return match.group(1)


def subformat_for(identity: str) -> str:
    return f"{SUBFORMAT_PREFIX}{agent_org(identity)}"


def is_custody_subformat(subformat: str) -> bool:
    return subformat.casefold().startswith(SUBFORMAT_PREFIX)


def validate_principal(principal: str) -> str:
    if not isinstance(principal, str) or not _PRINCIPAL.match(principal):
        raise CustodyTokenError(f"Invalid principal: {principal!r}.")
    return principal


def hash_principal(kind: str, value: str, salt: bytes) -> str:
    """Pseudonymise a principal another org should not learn, e.g. ``user:h:3fa1...``.

    The hash is keyed with the issuing org's salt so other orgs cannot test guesses;
    the issuer can still map it back for its own audit log.
    """
    if kind not in {"user", "external"}:
        raise ValueError("Only user and external principals are pseudonymised.")
    digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{kind}:h:{digest}"


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise CustodyTokenError("Invalid base64url.")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as error:
        raise CustodyTokenError("Invalid base64url.") from error


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def message_digest(message: NLIPMessage) -> str:
    """SHA-256 over the canonical JSON of ``message`` with every token part removed."""
    body = message.to_dict()
    if body.get("format") == AllowedFormat.token.value:
        # A bare token message has no content to bind beyond its type.
        body["content"] = None
    parts = [
        part
        for part in body.get("submessages", [])
        if part.get("format") != AllowedFormat.token.value
    ]
    if parts:
        body["submessages"] = parts
    else:
        body.pop("submessages", None)
    return "sha256:" + hashlib.sha256(_canonical_json(body)).hexdigest()


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CustodyClaims:
    iss: str
    aud: str
    nonce: str
    iat: int
    exp: int
    msg_digest: str
    principals: tuple[str, ...]
    v: int = VERSION

    def __post_init__(self) -> None:
        agent_org(self.iss)
        agent_org(self.aud)
        if self.v != VERSION:
            raise CustodyTokenError(f"Unsupported custody token version {self.v}.")
        if len(b64url_decode(self.nonce)) != NONCE_BYTES:
            raise CustodyTokenError("Custody nonce must be 128 bits.")
        if not (isinstance(self.iat, int) and isinstance(self.exp, int)):
            raise CustodyTokenError("iat and exp must be integers.")
        if self.exp <= self.iat:
            raise CustodyTokenError("exp must be after iat.")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.msg_digest):
            raise CustodyTokenError("Invalid msg_digest.")
        for principal in self.principals:
            validate_principal(principal)
        if list(self.principals) != sorted(set(self.principals)):
            raise CustodyTokenError("principals must be sorted and unique.")

    @staticmethod
    def normalize_principals(principals: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted({validate_principal(p) for p in principals}))

    def to_json(self) -> dict[str, object]:
        return {
            "v": self.v,
            "iss": self.iss,
            "aud": self.aud,
            "nonce": self.nonce,
            "iat": self.iat,
            "exp": self.exp,
            "msg_digest": self.msg_digest,
            "principals": list(self.principals),
        }

    @classmethod
    def from_json(cls, value: object) -> "CustodyClaims":
        if not isinstance(value, dict) or set(value) != _CLAIM_KEYS:
            raise CustodyTokenError("Custody claims have the wrong fields.")
        principals = value["principals"]
        if not isinstance(principals, list):
            raise CustodyTokenError("principals must be a list.")
        for key in ("iss", "aud", "nonce", "msg_digest"):
            if not isinstance(value[key], str):
                raise CustodyTokenError(f"{key} must be a string.")
        for key in ("v", "iat", "exp"):
            if type(value[key]) is not int:
                raise CustodyTokenError(f"{key} must be an integer.")
        return cls(
            v=value["v"],
            iss=value["iss"],
            aud=value["aud"],
            nonce=value["nonce"],
            iat=value["iat"],
            exp=value["exp"],
            msg_digest=value["msg_digest"],
            principals=tuple(principals),
        )


def encode_token(claims: CustodyClaims, private_key: Ed25519PrivateKey) -> str:
    claims_b64 = b64url_encode(_canonical_json(claims.to_json()))
    signature = private_key.sign(SIGNING_PREFIX + claims_b64.encode("ascii"))
    return f"{claims_b64}.{b64url_encode(signature)}"


def decode_unverified(content: object) -> tuple[CustodyClaims, str, bytes]:
    """Parse a token without trusting it. Returns (claims, signed b64 part, signature)."""
    if not isinstance(content, str) or content.count(".") != 1 or len(content) > 16_384:
        raise CustodyTokenError("Malformed custody token.")
    claims_b64, signature_b64 = content.split(".")
    try:
        raw = json.loads(b64url_decode(claims_b64))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CustodyTokenError("Custody claims are not JSON.") from error
    return CustodyClaims.from_json(raw), claims_b64, b64url_decode(signature_b64)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class CustodyVerifier:
    """Checks custody tokens addressed to ``local_identity``.

    A replay cache is mandatory. Tokens issued before ``not_before`` (by default the
    moment this verifier was created) are rejected, which closes the replay window an
    in-memory cache would otherwise reopen after a restart.
    """

    def __init__(
        self,
        local_identity: str,
        pinned_keys: Mapping[str, Ed25519PublicKey],
        replay_cache: ReplayCache,
        *,
        max_lifetime: int = 300,
        clock_skew: int = 30,
        clock: Callable[[], float] = time.time,
        not_before: int | None = None,
    ) -> None:
        agent_org(local_identity)
        if replay_cache is None:
            raise ValueError("A replay cache is mandatory.")
        for identity, key in pinned_keys.items():
            agent_org(identity)
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError(f"Pinned key for {identity} is not an Ed25519 key.")
        self.local_identity = local_identity
        self._keys = dict(pinned_keys)
        self._replay = replay_cache
        self._max_lifetime = max_lifetime
        self._skew = clock_skew
        self._clock = clock
        self._not_before = (
            int(clock()) - clock_skew if not_before is None else not_before
        )

    def verify(
        self, subformat: str, content: object, message: NLIPMessage
    ) -> CustodyClaims:
        """Fully verify one token for ``message``; consumes its nonce on success."""
        claims, claims_b64, signature = decode_unverified(content)
        if claims.aud != self.local_identity:
            raise CustodyTokenError(f"Token is addressed to {claims.aud}, not us.")
        key = self._keys.get(claims.iss)
        if key is None:
            raise CustodyTokenError(f"No pinned key for issuer {claims.iss}.")
        if subformat.casefold() != subformat_for(claims.iss):
            raise CustodyTokenError("Token subformat does not match its issuer.")
        try:
            key.verify(signature, SIGNING_PREFIX + claims_b64.encode("ascii"))
        except InvalidSignature as error:
            raise CustodyTokenError("Bad custody token signature.") from error

        now = int(self._clock())
        if claims.iat > now + self._skew:
            raise CustodyTokenError("Custody token issued in the future.")
        if claims.iat < self._not_before:
            raise CustodyTokenError("Custody token predates this verifier.")
        if claims.exp <= now - self._skew:
            raise CustodyTokenError("Custody token expired.")
        if claims.exp - claims.iat > self._max_lifetime:
            raise CustodyTokenError("Custody token lifetime too long.")
        if claims.msg_digest != message_digest(message):
            raise CustodyTokenError("Custody token is bound to a different message.")
        # Consume the nonce last, so a rejected token cannot burn a valid one's nonce.
        if not self._replay.check_and_add(claims.iss, claims.nonce, claims.exp):
            raise CustodyTokenError("Custody token replayed.")
        return claims

    def select(self, message: NLIPMessage) -> CustodyClaims | None:
        """Return the one verified custody token addressed to us, or ``None``.

        Tokens addressed to someone else are ignored: they are reflected echoes of our
        own outgoing tokens (ECMA-430 §6.2) or noise. ``None`` means the sender gave no
        custody token for us and must be treated as ``unknown``. More than one token
        addressed to us, or one that fails verification, raises.
        """
        addressed: list[tuple[str, object]] = []
        for token in message.token_submessages():
            if not is_custody_subformat(token.subformat):
                continue
            try:
                claims, _, _ = decode_unverified(token.content)
            except CustodyTokenError:
                continue
            if claims.aud == self.local_identity:
                addressed.append((token.subformat, token.content))
        if not addressed:
            return None
        if len(addressed) > 1:
            raise CustodyTokenError("More than one custody token addressed to us.")
        subformat, content = addressed[0]
        return self.verify(subformat, content, message)


def strip_custody_tokens(message: NLIPMessage) -> NLIPMessage:
    """Copy of ``message`` without custody token parts (so the SDK never stores them)."""
    cleaned = message.model_copy(deep=True)
    if cleaned.submessages:
        kept = [
            part
            for part in cleaned.submessages
            if not (
                part.format == AllowedFormat.token
                and is_custody_subformat(part.subformat)
            )
        ]
        cleaned.submessages = kept or None
    return cleaned
