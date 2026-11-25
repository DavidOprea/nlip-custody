"""Custody: boundary-computed influence provenance carried across NLIP agents."""

from .consent import ConsentIssuer, ConsentVerifier, args_digest
from .guard import CustodyToolBlocked, CustodyToolGuard, ToolDecision
from .replay import ReplayCache
from .token import (
    CustodyClaims,
    CustodyTokenError,
    CustodyVerifier,
    hash_principal,
    message_digest,
    strip_custody_tokens,
    subformat_for,
)

__all__ = [
    "ConsentIssuer",
    "ConsentVerifier",
    "CustodyToolBlocked",
    "CustodyToolGuard",
    "ToolDecision",
    "args_digest",
    "CustodyClaims",
    "CustodySigner",
    "CustodyTokenError",
    "CustodyVerifier",
    "RemoteSigner",
    "ReplayCache",
    "SignerError",
    "hash_principal",
    "message_digest",
    "strip_custody_tokens",
    "subformat_for",
]

_SIGNER_NAMES = {"CustodySigner", "RemoteSigner", "SignerError"}


def __getattr__(name: str):
    # Imported lazily so `python -m security_extensions.custody.signer` does not find
    # the signer module already loaded by this package (a runpy warning).
    if name in _SIGNER_NAMES:
        from . import signer

        return getattr(signer, name)
    raise AttributeError(name)
