import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nlip_sdk import NLIPMessage, NLIPServer, NLIPSession
from security_extensions.custody import (
    CustodyClaims,
    CustodySigner,
    CustodyTokenError,
    CustodyVerifier,
    RemoteSigner,
    ReplayCache,
    SignerError,
    hash_principal,
    message_digest,
    strip_custody_tokens,
)
from security_extensions.custody.keys import (
    generate_private_key,
    load_pinned_keys,
    public_key_b64,
)
from security_extensions.custody.token import b64url_decode, b64url_encode

ASSISTANT = "agent:acme/assistant"
FINANCE = "agent:fin/finance"
ROGUE = "agent:evil/rogue"
PRINCIPALS = ["user:h:abc", "external:h:def", "agent:acme/inbox"]


class Clock:
    def __init__(self, now: float = 1_764_000_000) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def world():
    clock = Clock()
    keys = {ASSISTANT: Ed25519PrivateKey.generate(), ROGUE: Ed25519PrivateKey.generate()}
    signer = CustodySigner(ASSISTANT, keys[ASSISTANT], clock=clock)
    verifier = CustodyVerifier(
        FINANCE,
        {ASSISTANT: keys[ASSISTANT].public_key()},  # the rogue is NOT pinned
        ReplayCache(clock=clock),
        clock=clock,
    )
    return clock, keys, signer, verifier


def attach(message: NLIPMessage, signer: CustodySigner, aud: str = FINANCE) -> NLIPMessage:
    token = signer.sign(aud, message_digest(message), PRINCIPALS)
    out = message.model_copy(deep=True)
    out.add_token(token, signer.subformat)
    return out


def test_round_trip_returns_sorted_principals(world) -> None:
    _, _, signer, verifier = world
    message = attach(NLIPMessage.text("pay invoice 4471"), signer)
    claims = verifier.select(message)
    assert claims is not None
    assert claims.iss == ASSISTANT and claims.aud == FINANCE
    assert claims.principals == tuple(sorted(PRINCIPALS))


def test_digest_ignores_tokens_but_binds_everything_else() -> None:
    base = NLIPMessage.text("hello")
    with_tokens = base.model_copy(deep=True)
    with_tokens.add_token("abc", "conversation_x")
    with_tokens.add_token("def", "custody_acme")
    assert message_digest(base) == message_digest(with_tokens)
    assert message_digest(base) != message_digest(NLIPMessage.text("hello!"))
    assert message_digest(base) != message_digest(NLIPMessage.text("hello", "French"))
    assert message_digest(base) != message_digest(NLIPMessage.control("hello"))


def test_no_token_means_unknown_caller(world) -> None:
    _, _, _, verifier = world
    assert verifier.select(NLIPMessage.text("hi")) is None


def test_replay_is_rejected(world) -> None:
    _, _, signer, verifier = world
    message = attach(NLIPMessage.text("pay"), signer)
    assert verifier.select(message) is not None
    with pytest.raises(CustodyTokenError, match="replayed"):
        verifier.select(message)


def test_token_moved_to_another_message_is_rejected(world) -> None:
    _, _, signer, verifier = world
    original = attach(NLIPMessage.text("summarise my inbox"), signer)
    moved = NLIPMessage.text("pay invoice 4471 to account 9921")
    for token in original.token_submessages():
        moved.add_submessage(token)
    with pytest.raises(CustodyTokenError, match="different message"):
        verifier.select(moved)


def test_principals_cannot_be_edited(world) -> None:
    _, _, signer, verifier = world
    message = attach(NLIPMessage.text("pay"), signer)
    token = message.token_submessages()[-1]
    claims_b64, sig = str(token.content).split(".")
    claims = json.loads(b64url_decode(claims_b64))
    claims["principals"] = ["user:h:abc"]  # drop the external sender
    forged = b64url_encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    token.content = f"{forged}.{sig}"
    with pytest.raises(CustodyTokenError, match="signature"):
        verifier.select(message)


def test_unpinned_issuer_is_rejected(world) -> None:
    clock, keys, _, verifier = world
    rogue = CustodySigner(ROGUE, keys[ROGUE], clock=clock)
    with pytest.raises(CustodyTokenError, match="No pinned key"):
        verifier.select(attach(NLIPMessage.text("pay"), rogue))


def test_rogue_key_cannot_sign_as_pinned_issuer(world) -> None:
    clock, keys, _, verifier = world
    impostor = CustodySigner(ASSISTANT, keys[ROGUE], clock=clock)
    with pytest.raises(CustodyTokenError, match="signature"):
        verifier.select(attach(NLIPMessage.text("pay"), impostor))


def test_expired_and_future_tokens_are_rejected(world) -> None:
    clock, _, signer, verifier = world
    stale = attach(NLIPMessage.text("pay"), signer)
    clock.now += 61 + 30
    with pytest.raises(CustodyTokenError, match="expired"):
        verifier.select(stale)

    future_signer = CustodySigner(
        ASSISTANT, signer._key, clock=lambda: clock.now + 3600  # noqa: SLF001
    )
    with pytest.raises(CustodyTokenError, match="future"):
        verifier.select(attach(NLIPMessage.text("pay"), future_signer))


def test_tokens_from_before_verifier_start_are_rejected() -> None:
    """An in-memory replay cache is lost on restart; old tokens must not come back."""
    clock = Clock()
    key = Ed25519PrivateKey.generate()
    old = attach(NLIPMessage.text("pay"), CustodySigner(ASSISTANT, key, clock=clock))
    clock.now += 45  # verifier restarts; token still inside its 60 s lifetime
    restarted = CustodyVerifier(
        FINANCE, {ASSISTANT: key.public_key()}, ReplayCache(clock=clock), clock=clock
    )
    with pytest.raises(CustodyTokenError, match="predates"):
        restarted.select(old)


def test_reflected_echo_is_ignored(world) -> None:
    """ECMA-430 §6.2: our own token comes back to us; it is not a token *for* us."""
    clock, keys, signer, _ = world
    assistant_verifier = CustodyVerifier(
        ASSISTANT, {ASSISTANT: keys[ASSISTANT].public_key()}, ReplayCache(clock=clock),
        clock=clock,
    )
    request = attach(NLIPMessage.text("pay"), signer, aud=FINANCE)

    class Finance(NLIPServer):
        async def handle(self, message: NLIPMessage, session: NLIPSession) -> str:
            return "paid"

    response = asyncio.run(Finance("finance").process_exchange(request))
    assert any(t.subformat == "custody_acme" for t in response.token_submessages())
    assert assistant_verifier.select(response) is None


def test_two_tokens_addressed_to_us_are_rejected(world) -> None:
    _, _, signer, verifier = world
    message = attach(NLIPMessage.text("pay"), signer)
    message.add_token(
        signer.sign(FINANCE, message_digest(message), ["unknown"]), signer.subformat
    )
    with pytest.raises(CustodyTokenError, match="More than one"):
        verifier.select(message)


def test_garbage_custody_tokens_are_ignored_not_trusted(world) -> None:
    _, _, signer, verifier = world
    message = NLIPMessage.text("pay")
    message.add_token("not-a-token", "custody_acme")
    message.add_token("a.b", "custody_acme")
    assert verifier.select(message) is None
    good = attach(message, signer)
    assert verifier.select(good) is not None


def test_subformat_must_match_issuer(world) -> None:
    _, _, signer, verifier = world
    message = NLIPMessage.text("pay")
    message.add_token(
        signer.sign(FINANCE, message_digest(message), PRINCIPALS), "custody_fin"
    )
    with pytest.raises(CustodyTokenError, match="subformat"):
        verifier.select(message)


def test_signer_rules() -> None:
    key = Ed25519PrivateKey.generate()
    signer = CustodySigner(ASSISTANT, key, allowed_audiences={FINANCE})
    with pytest.raises(CustodyTokenError, match="not allowed"):
        signer.sign("agent:hr/hr", "sha256:" + "0" * 64, [])
    with pytest.raises(CustodyTokenError, match="Invalid principal"):
        signer.sign(FINANCE, "sha256:" + "0" * 64, ["root"])
    with pytest.raises(ValueError):
        CustodySigner(ASSISTANT, key, ttl=3600)
    a = CustodyClaims.from_json(
        json.loads(b64url_decode(signer.sign(FINANCE, "sha256:" + "0" * 64, []).split(".")[0]))
    )
    b = CustodyClaims.from_json(
        json.loads(b64url_decode(signer.sign(FINANCE, "sha256:" + "0" * 64, []).split(".")[0]))
    )
    assert a.nonce != b.nonce and a.iss == ASSISTANT


def test_replay_cache_expires_and_fails_closed_when_full() -> None:
    clock = Clock()
    cache = ReplayCache(max_entries=2, clock_skew=0, clock=clock)
    exp = int(clock.now) + 10
    assert cache.check_and_add("i", "n1", exp)
    assert not cache.check_and_add("i", "n1", exp)
    assert cache.check_and_add("i", "n2", exp)
    assert not cache.check_and_add("i", "n3", exp)  # full of live nonces
    clock.now += 11
    assert cache.check_and_add("i", "n3", int(clock.now) + 10)
    assert len(cache) == 1


def test_strip_custody_tokens_keeps_other_tokens() -> None:
    message = NLIPMessage.text("hi")
    message.add_token("c", "conversation_x")
    message.add_token("t", "custody_acme")
    stripped = strip_custody_tokens(message)
    assert [t.subformat for t in stripped.token_submessages()] == ["conversation_x"]
    assert message.extract_token("custody_acme") == "t"  # original untouched


def test_hash_principal_is_keyed() -> None:
    a = hash_principal("user", "alice", b"acme-salt")
    assert a.startswith("user:h:") and "alice" not in a
    assert a != hash_principal("user", "alice", b"other-salt")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_signer_runs_as_separate_process(tmp_path: Path) -> None:
    key_path = tmp_path / "acme_assistant.pem"
    public = public_key_b64(generate_private_key(key_path))
    address = f"tcp:127.0.0.1:{_free_port()}"
    authkey = secrets.token_urlsafe(24)
    env = {**os.environ, "CUSTODY_SIGNER_AUTHKEY": authkey}
    proc = subprocess.Popen(
        [sys.executable, "-m", "security_extensions.custody.signer",
         "--identity", ASSISTANT, "--key", str(key_path), "--address", address],
        env=env, cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        remote = None
        deadline = time.monotonic() + 15
        while remote is None:
            try:
                remote = RemoteSigner(address, authkey.encode(), identity=ASSISTANT)
            except SignerError:
                if time.monotonic() > deadline or proc.poll() is not None:
                    raise
                time.sleep(0.1)
        assert remote.public_key == public

        verifier = CustodyVerifier(
            FINANCE, load_pinned_keys({ASSISTANT: public}), ReplayCache()
        )
        message = NLIPMessage.text("pay")
        message.add_token(
            remote.sign(FINANCE, message_digest(message), PRINCIPALS), "custody_acme"
        )
        assert verifier.select(message).principals == tuple(sorted(PRINCIPALS))

        with pytest.raises(SignerError, match="Invalid principal"):
            remote.sign(FINANCE, message_digest(message), ["root"])
        remote.close()

        with pytest.raises(Exception):
            RemoteSigner(address, b"wrong-authkey-wrong-authkey")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
