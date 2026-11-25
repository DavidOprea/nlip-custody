"""Ed25519 key helpers for custody signers and pinned public keys.

Generate a key for one agent (keep the private key where only the signer can read it)::

    python -m security_extensions.custody.keys gen keys/acme_assistant.pem

The printed public key goes into every peer's pinned-keys config.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .token import agent_org, b64url_decode, b64url_encode


def generate_private_key(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    """Create a new key at ``path`` (refusing to overwrite) with owner-only access."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    return key


def load_private_key(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key.")
    return key


def public_key_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return b64url_encode(
        public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def load_public_key(text: str) -> Ed25519PublicKey:
    raw = b64url_decode(text)
    if len(raw) != 32:
        raise ValueError("Ed25519 public keys are 32 bytes.")
    return Ed25519PublicKey.from_public_bytes(raw)


def load_pinned_keys(config: Mapping[str, str]) -> dict[str, Ed25519PublicKey]:
    """``{"agent:acme/assistant": "<b64url public key>", ...}`` -> key objects."""
    pinned: dict[str, Ed25519PublicKey] = {}
    for identity, text in config.items():
        agent_org(identity)
        pinned[identity] = load_public_key(text)
    return pinned


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("gen", help="generate a private key and print its public key")
    gen.add_argument("path")
    show = sub.add_parser("pub", help="print the public key of a private key file")
    show.add_argument("path")
    args = parser.parse_args(argv)
    if args.command == "gen":
        print(public_key_b64(generate_private_key(args.path)))
    else:
        print(public_key_b64(load_private_key(args.path)))


if __name__ == "__main__":
    main()
