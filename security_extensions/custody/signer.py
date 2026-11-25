"""Custody signing, kept in a separate process so agent code never holds the key.

The signer, not its caller, chooses ``iss``, ``nonce``, ``iat`` and ``exp``. A caller
(the custody SE inside the agent process) supplies only the audience, the message
digest and the principal set. So a compromised agent can at worst get short-lived
tokens in its own name; it cannot read the key, mint tokens for another issuer,
extend lifetimes, or reuse nonces.

Run one signer per agent identity::

    set CUSTODY_SIGNER_AUTHKEY=<random secret shared with the agent's SE>
    python -m security_extensions.custody.signer --identity agent:acme/assistant ^
        --key keys/acme_assistant.pem --address tcp:127.0.0.1:47011

Addresses: ``tcp:<host>:<port>`` (loopback only), ``pipe:<name>`` (Windows named
pipe), or ``unix:<path>`` (POSIX). The wire protocol is one JSON object per
``send_bytes`` frame after ``multiprocessing.connection``'s HMAC authkey handshake;
nothing is ever unpickled.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import time
from collections.abc import Callable, Collection, Iterable
from multiprocessing.connection import Client, Connection, Listener
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import load_private_key, public_key_b64
from .token import (
    NONCE_BYTES,
    CustodyClaims,
    CustodyTokenError,
    agent_org,
    b64url_encode,
    encode_token,
    subformat_for,
)

MAX_FRAME = 64 * 1024


class Signer(Protocol):
    identity: str

    def sign(self, aud: str, msg_digest: str, principals: Iterable[str]) -> str: ...


class SignerError(RuntimeError):
    """The signer refused a request or could not be reached."""


class CustodySigner:
    """Holds one agent's private key and mints custody tokens under fixed rules."""

    def __init__(
        self,
        identity: str,
        private_key: Ed25519PrivateKey,
        *,
        ttl: int = 60,
        allowed_audiences: Collection[str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        agent_org(identity)
        if not 1 <= ttl <= 300:
            raise ValueError("ttl must be between 1 and 300 seconds.")
        self.identity = identity
        self.subformat = subformat_for(identity)
        self._key = private_key
        self._ttl = ttl
        self._audiences = None if allowed_audiences is None else set(allowed_audiences)
        self._clock = clock

    @property
    def public_key(self) -> str:
        return public_key_b64(self._key)

    def sign(self, aud: str, msg_digest: str, principals: Iterable[str]) -> str:
        if self._audiences is not None and aud not in self._audiences:
            raise CustodyTokenError(f"Audience {aud!r} is not allowed for this signer.")
        if aud == self.identity:
            raise CustodyTokenError("A signer does not address tokens to itself.")
        now = int(self._clock())
        claims = CustodyClaims(
            iss=self.identity,
            aud=aud,
            nonce=b64url_encode(secrets.token_bytes(NONCE_BYTES)),
            iat=now,
            exp=now + self._ttl,
            msg_digest=msg_digest,
            principals=CustodyClaims.normalize_principals(principals),
        )
        return encode_token(claims, self._key)


# ---------------------------------------------------------------------------
# Process boundary
# ---------------------------------------------------------------------------


def parse_address(address: str) -> tuple[Any, str]:
    """Return (multiprocessing address, family) for a ``kind:value`` string."""
    kind, _, value = address.partition(":")
    if kind == "tcp":
        host, _, port = value.rpartition(":")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("The custody signer only listens on loopback.")
        return (host, int(port)), "AF_INET"
    if kind == "pipe":
        name = value if value.startswith("\\\\.\\pipe\\") else f"\\\\.\\pipe\\{value}"
        return name, "AF_PIPE"
    if kind == "unix":
        return value, "AF_UNIX"
    raise ValueError(f"Unknown signer address {address!r}.")


def _send(conn: Connection, value: dict[str, Any]) -> None:
    conn.send_bytes(json.dumps(value).encode("utf-8"))


def _recv(conn: Connection) -> dict[str, Any]:
    value = json.loads(conn.recv_bytes(MAX_FRAME).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Signer frames must be JSON objects.")
    return value


def handle_request(signer: CustodySigner, request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    if op == "identity":
        return {"identity": signer.identity, "public_key": signer.public_key}
    if op == "sign":
        principals = request.get("principals")
        aud, digest = request.get("aud"), request.get("msg_digest")
        if not (
            isinstance(aud, str)
            and isinstance(digest, str)
            and isinstance(principals, list)
            and all(isinstance(p, str) for p in principals)
        ):
            return {"error": "sign needs aud, msg_digest and a list of principals."}
        try:
            return {"token": signer.sign(aud, digest, principals)}
        except (CustodyTokenError, ValueError) as error:
            return {"error": str(error)}
    return {"error": f"Unknown op {op!r}."}


def _serve_connection(conn: Connection, signer: CustodySigner) -> None:
    with conn:
        while True:
            try:
                request = _recv(conn)
            except (EOFError, OSError):
                return
            except (ValueError, UnicodeDecodeError):
                response: dict[str, Any] = {"error": "Malformed request."}
            else:
                response = handle_request(signer, request)
            try:
                _send(conn, response)
            except OSError:
                return


def serve(
    signer: CustodySigner,
    address: str,
    authkey: bytes,
    *,
    ready: threading.Event | None = None,
    stop: threading.Event | None = None,
) -> None:
    """Accept authenticated connections until ``stop`` is set (or forever)."""
    if len(authkey) < 16:
        raise ValueError("Signer authkey must be at least 16 bytes.")
    mp_address, family = parse_address(address)
    with Listener(mp_address, family=family, authkey=authkey) as listener:
        if ready is not None:
            ready.set()
        while stop is None or not stop.is_set():
            try:
                conn = listener.accept()
            except Exception:  # failed handshake (wrong authkey) etc.
                continue
            if stop is not None and stop.is_set():
                conn.close()
                break
            threading.Thread(
                target=_serve_connection, args=(conn, signer), daemon=True
            ).start()


class RemoteSigner:
    """Client for a signer process; same ``sign`` interface as :class:`CustodySigner`.

    Keeps one connection open and reconnects once on failure. Thread-safe, so the
    async SE can call it via ``asyncio.to_thread``.
    """

    def __init__(self, address: str, authkey: bytes, *, identity: str | None = None):
        self._address, self._family = parse_address(address)
        self._authkey = authkey
        self._conn: Connection | None = None
        self._lock = threading.Lock()
        info = self._call({"op": "identity"})
        self.identity: str = info["identity"]
        self.public_key: str = info["public_key"]
        if identity is not None and identity != self.identity:
            raise SignerError(
                f"Signer at {address} is {self.identity!r}, expected {identity!r}."
            )

    def _connect(self) -> Connection:
        return Client(self._address, family=self._family, authkey=self._authkey)

    def _call(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._conn is None:
                        self._conn = self._connect()
                    _send(self._conn, request)
                    response = _recv(self._conn)
                    break
                except (OSError, EOFError) as error:
                    if self._conn is not None:
                        self._conn.close()
                    self._conn = None
                    if attempt == 2:
                        raise SignerError(f"Signer unreachable: {error}") from error
        if "error" in response:
            raise SignerError(str(response["error"]))
        return response

    def sign(self, aud: str, msg_digest: str, principals: Iterable[str]) -> str:
        response = self._call(
            {
                "op": "sign",
                "aud": aud,
                "msg_digest": msg_digest,
                "principals": list(principals),
            }
        )
        return str(response["token"])

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run a custody signer process.")
    parser.add_argument("--identity", required=True, help="agent:<org>/<name>")
    parser.add_argument("--key", required=True, help="path to the Ed25519 PEM key")
    parser.add_argument("--address", required=True, help="tcp:/pipe:/unix: address")
    parser.add_argument("--authkey-env", default="CUSTODY_SIGNER_AUTHKEY")
    parser.add_argument("--ttl", type=int, default=60)
    parser.add_argument("--audience", action="append", help="allowed audience")
    args = parser.parse_args(argv)
    authkey = os.environ.get(args.authkey_env, "").encode("utf-8")
    if len(authkey) < 16:
        sys.exit(f"Set {args.authkey_env} to a secret of at least 16 characters.")
    signer = CustodySigner(
        args.identity,
        load_private_key(args.key),
        ttl=args.ttl,
        allowed_audiences=args.audience,
    )
    print(f"custody signer {signer.identity} on {args.address}", flush=True)
    serve(signer, args.address, authkey)


if __name__ == "__main__":
    main()
