"""Signed consent requests: what a blocked tool call asks the user to approve.

When the tool guard blocks a call that consent may release, the agent's custody SE
signs a *consent request* with that agent's key (through its signer process) and
attaches it to its reply. Each hop on the way back collects it at client ingress and
forwards it, unchanged, on its own reply, so it reaches the user's client. No model
can read, drop or reword it: like custody tokens, it never enters model context.

The user's client verifies it (pinned key, freshness, digest), shows the exact tool,
arguments and offending principals, and on approval mints a consent token from
*those* arguments. A tricked model can still tell the user something misleading in
prose, but the approval is built from the signed request, not from the prose.

Wire form (an NLIP token part)::

    format="token", subformat="consentreq_<org>",
    content="<b64url(claims)>.<b64url(ed25519 sig over REQUEST_PREFIX + claims)>"
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .consent import ConsentIssuer, args_digest
from .token import (
    NONCE_BYTES,
    CustodyTokenError,
    agent_org,
    b64url_decode,
    b64url_encode,
    validate_principal,
)

REQUEST_PREFIX = b"nlip-consent-request-v1."
REQUEST_SUBFORMAT_PREFIX = "consentreq_"
MAX_REQUEST_BYTES = 8192
_KEYS = {"v", "typ", "iss", "tool", "args", "args_digest", "offenders", "nonce", "iat", "exp"}


def request_subformat(issuer: str) -> str:
    return f"{REQUEST_SUBFORMAT_PREFIX}{agent_org(issuer)}"


def is_request_subformat(subformat: str) -> bool:
    return subformat.casefold().startswith(REQUEST_SUBFORMAT_PREFIX)


@dataclass(frozen=True, slots=True)
class ConsentRequestClaims:
    iss: str                    # the agent whose tool call was blocked
    tool: str
    args: dict[str, Any]        # the exact arguments; the approval is built from these
    args_digest: str
    offenders: tuple[str, ...]  # principals not allowed to request this tool
    nonce: str
    iat: int
    exp: int
    v: int = 1
    typ: str = "consent_request"

    def to_json(self) -> dict[str, object]:
        return {
            "v": self.v, "typ": self.typ, "iss": self.iss, "tool": self.tool,
            "args": self.args, "args_digest": self.args_digest,
            "offenders": list(self.offenders), "nonce": self.nonce,
            "iat": self.iat, "exp": self.exp,
        }

    @classmethod
    def from_json(cls, value: object) -> "ConsentRequestClaims":
        if not isinstance(value, dict) or set(value) != _KEYS:
            raise CustodyTokenError("Consent request has the wrong fields.")
        if value["v"] != 1 or value["typ"] != "consent_request":
            raise CustodyTokenError("Unsupported consent request.")
        if not isinstance(value["args"], dict) or not isinstance(value["offenders"], list):
            raise CustodyTokenError("Consent request args/offenders have the wrong type.")
        for key in ("iss", "tool", "args_digest", "nonce"):
            if not isinstance(value[key], str):
                raise CustodyTokenError(f"{key} must be a string.")
        for key in ("iat", "exp"):
            if type(value[key]) is not int:
                raise CustodyTokenError(f"{key} must be an integer.")
        claims = cls(
            iss=value["iss"], tool=value["tool"], args=dict(value["args"]),
            args_digest=value["args_digest"],
            offenders=tuple(validate_principal(p) for p in value["offenders"]),
            nonce=value["nonce"], iat=value["iat"], exp=value["exp"],
        )
        agent_org(claims.iss)
        if claims.args_digest != args_digest(claims.args):
            raise CustodyTokenError("Consent request digest does not match its arguments.")
        return claims


def encode_request(claims: ConsentRequestClaims, key: Ed25519PrivateKey) -> str:
    body = json.dumps(claims.to_json(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)
    claims_b64 = b64url_encode(body.encode("utf-8"))
    if len(claims_b64) > MAX_REQUEST_BYTES:
        raise CustodyTokenError("Consent request too large.")
    return f"{claims_b64}.{b64url_encode(key.sign(REQUEST_PREFIX + claims_b64.encode()))}"


def new_request_claims(
    issuer: str, tool: str, args: Mapping[str, Any], offenders: Iterable[str],
    *, ttl: int, now: int,
) -> ConsentRequestClaims:
    import secrets

    plain = json.loads(json.dumps(dict(args), default=str))  # JSON-safe, as the user will see it
    return ConsentRequestClaims(
        iss=issuer, tool=tool, args=plain, args_digest=args_digest(plain),
        offenders=tuple(sorted({validate_principal(p) for p in offenders})),
        nonce=b64url_encode(secrets.token_bytes(NONCE_BYTES)), iat=now, exp=now + ttl,
    )


def decode_request_unverified(content: object) -> tuple[ConsentRequestClaims, str, bytes]:
    if not isinstance(content, str) or content.count(".") != 1 or len(content) > 2 * MAX_REQUEST_BYTES:
        raise CustodyTokenError("Malformed consent request.")
    claims_b64, sig_b64 = content.split(".")
    try:
        raw = json.loads(b64url_decode(claims_b64))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CustodyTokenError("Consent request is not JSON.") from error
    return ConsentRequestClaims.from_json(raw), claims_b64, b64url_decode(sig_b64)


@dataclass
class ConsentDesk:
    """The user's side: verify incoming requests, show them, approve chosen ones.

    Only requests signed by a pinned participating agent are shown. Each request is
    shown once (deduplicated by issuer and nonce), and expired ones are dropped.
    """

    pinned_keys: Mapping[str, Ed25519PublicKey]
    clock: Callable[[], float] = time.time
    clock_skew: int = 30
    max_lifetime: int = 3600
    _seen: set[tuple[str, str]] = field(default_factory=set, repr=False)

    def verify(self, content: object) -> ConsentRequestClaims:
        claims, claims_b64, sig = decode_request_unverified(content)
        key = self.pinned_keys.get(claims.iss)
        if key is None:
            raise CustodyTokenError(f"No pinned key for {claims.iss}.")
        try:
            key.verify(sig, REQUEST_PREFIX + claims_b64.encode("ascii"))
        except InvalidSignature as error:
            raise CustodyTokenError("Bad consent request signature.") from error
        now = int(self.clock())
        if claims.iat > now + self.clock_skew:
            raise CustodyTokenError("Consent request issued in the future.")
        if claims.exp <= now - self.clock_skew:
            raise CustodyTokenError("Consent request expired.")
        if claims.exp - claims.iat > self.max_lifetime:
            raise CustodyTokenError("Consent request lifetime too long.")
        return claims

    def pending(self, tokens: Iterable[str]) -> tuple[list[ConsentRequestClaims], list[str]]:
        """Verified, not-yet-shown requests, and the reasons others were rejected."""
        shown: list[ConsentRequestClaims] = []
        rejected: list[str] = []
        for token in tokens:
            try:
                claims = self.verify(token)
            except CustodyTokenError as error:
                rejected.append(str(error))
                continue
            if (claims.iss, claims.nonce) in self._seen:
                continue
            self._seen.add((claims.iss, claims.nonce))
            shown.append(claims)
        return shown, rejected

    @staticmethod
    def approve(request: ConsentRequestClaims, issuer: ConsentIssuer) -> str:
        """A consent token for exactly the signed call, addressed to the agent that asked."""
        return issuer.approve(request.iss, request.tool, request.args)

    @staticmethod
    def describe(request: ConsentRequestClaims) -> str:
        args = ", ".join(f"{k}={v}" for k, v in sorted(request.args.items()))
        return (f"{request.iss} asks to run {request.tool}({args}); "
                f"influenced by: {', '.join(request.offenders)}")
