"""Regression tests for the Chutes client-side key binding and for encrypted-request
message validation.

Key binding: the normalized verdict binds ``report_data`` to
``e2e_pubkeys[instance_id]``, but the request is sealed to
``e2e_instances[i].e2e_pubkey``. A relay that binds one key while serving another
must NOT be able to make the client encrypt to an unverified key.
``_select_verified_chutes_key`` closes that gap; these tests assert both the happy
path and the two substitution attacks fail closed.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from anonrouter_confidential.client import (
    ConfidentialError,
    _select_verified_chutes_key,
    _validate_e2ee_messages,
)

_NONCE = "a1b2c3d4e5f6071829384756a1b2c3d4e5f6071829384756a1b2c3d4e5f60718"  # 64 hex
_INSTANCE_ID = "11111111-2222-4333-8444-555555555555"
_INSTANCE_NONCE = "instance-nonce-0001"

# One 48-byte measurement identity, shared by the quote and the allowlist entry.
_MRTD = bytes(range(48))
_RTMR0 = bytes([0xAA]) * 48
_RTMR1 = bytes([0xBB]) * 48
_RTMR2 = bytes([0xCC]) * 48
_RTMR3 = bytes([0xDD]) * 48

_ALLOWLIST = [
    {
        "name": "chutes-test",
        "mrTd": _MRTD.hex(),
        "rtmr0": _RTMR0.hex(),
        "rtmr1": _RTMR1.hex(),
        "rtmr2": _RTMR2.hex(),
        "rtmr3": _RTMR3.hex(),
    }
]


def _mlkem_pubkey(fill: int) -> str:
    """A 1184-byte ML-KEM public key, base64. Contents are opaque to the selector."""
    return base64.b64encode(bytes([fill]) * 1184).decode()


def _build_quote(report_data_first32: bytes) -> str:
    buf = bytearray(632)
    buf[0:2] = (4).to_bytes(2, "little")  # version
    buf[4:8] = (0x81).to_bytes(4, "little")  # teeType (Intel TDX)
    # td_attributes @168 left all-zero -> debug disabled.
    buf[184:232] = _MRTD
    buf[376:424] = _RTMR0
    buf[424:472] = _RTMR1
    buf[472:520] = _RTMR2
    buf[520:568] = _RTMR3
    assert len(report_data_first32) == 32
    buf[568:600] = report_data_first32
    return buf.hex()


def _evidence(*, served_key: str, bound_key: str, record_key: str | None) -> dict:
    """A Chutes attestation where the quote binds ``bound_key`` in report_data,
    ``e2e_instances[0].e2e_pubkey`` serves ``served_key`` (the key the client would
    encrypt to), and ``e2e_pubkeys[instance_id]`` is ``record_key`` (or omitted)."""
    report_first = hashlib.sha256((_NONCE + bound_key).encode("utf-8")).digest()  # 32 bytes
    quote = _build_quote(report_first)
    payload: dict = {
        "e2e_instances": [
            {"instance_id": _INSTANCE_ID, "e2e_pubkey": served_key, "nonces": [_INSTANCE_NONCE]}
        ],
        "evidence": [{"instance_id": _INSTANCE_ID, "quote": quote}],
        "failed_instance_ids": [],
    }
    if record_key is not None:
        payload["e2e_pubkeys"] = {_INSTANCE_ID: record_key}
    return payload


def test_chutes_valid_binding_returns_verified_key() -> None:
    key = _mlkem_pubkey(0x01)
    evidence = _evidence(served_key=key, bound_key=key, record_key=key)
    instance_id, instance_nonce, pubkey = _select_verified_chutes_key(evidence, _NONCE, _ALLOWLIST)
    assert instance_id == _INSTANCE_ID
    assert instance_nonce == _INSTANCE_NONCE
    assert pubkey == base64.b64decode(key)


def test_chutes_substituted_served_key_with_record_disagree_fails_closed() -> None:
    # Attack A: bind + record the real key, but serve an attacker key. The records
    # must disagree with the served key -> reject.
    real = _mlkem_pubkey(0x01)
    attacker = _mlkem_pubkey(0x02)
    evidence = _evidence(served_key=attacker, bound_key=real, record_key=real)
    with pytest.raises(ConfidentialError, match="records disagree"):
        _select_verified_chutes_key(evidence, _NONCE, _ALLOWLIST)


def test_chutes_served_key_not_bound_to_nonce_fails_closed() -> None:
    # Attack B: no e2e_pubkeys record, serve an attacker key the quote never bound.
    # The report_data nonce/key binding must fail -> reject.
    real = _mlkem_pubkey(0x01)
    attacker = _mlkem_pubkey(0x02)
    evidence = _evidence(served_key=attacker, bound_key=real, record_key=None)
    with pytest.raises(ConfidentialError, match="not bound to this request's nonce"):
        _select_verified_chutes_key(evidence, _NONCE, _ALLOWLIST)


def test_chutes_measurements_off_allowlist_fails_closed() -> None:
    key = _mlkem_pubkey(0x01)
    evidence = _evidence(served_key=key, bound_key=key, record_key=key)
    with pytest.raises(ConfidentialError, match="not on the reviewed allowlist"):
        _select_verified_chutes_key(evidence, _NONCE, [])


def test_chutes_wrong_size_key_fails_closed() -> None:
    short = base64.b64encode(b"\x01" * 100).decode()
    evidence = _evidence(served_key=short, bound_key=short, record_key=short)
    with pytest.raises(ConfidentialError, match="wrong size"):
        _select_verified_chutes_key(evidence, _NONCE, _ALLOWLIST)


# -- encrypted-request message validation -------------------------------------


def test_validate_rejects_tool_role() -> None:
    with pytest.raises(ConfidentialError, match="tool messages"):
        _validate_e2ee_messages([{"role": "tool", "content": "x"}])


def test_validate_rejects_non_string_content() -> None:
    with pytest.raises(ConfidentialError, match="text content only"):
        _validate_e2ee_messages([{"role": "user", "content": {"image": "..."}}])


def test_validate_rejects_empty_list() -> None:
    with pytest.raises(ConfidentialError, match="no messages"):
        _validate_e2ee_messages([])


def test_validate_requires_a_user_message() -> None:
    with pytest.raises(ConfidentialError, match="needs a user message"):
        _validate_e2ee_messages([{"role": "system", "content": "be nice"}])


def test_validate_rejects_oversized_message() -> None:
    with pytest.raises(ConfidentialError, match="too long"):
        _validate_e2ee_messages([{"role": "user", "content": "a" * (128 * 1024 + 1)}])


def test_validate_malformed_message_raises_confidential_error_not_keyerror() -> None:
    with pytest.raises(ConfidentialError):
        _validate_e2ee_messages(["not-a-dict"])


def test_validate_accepts_multi_turn_history() -> None:
    _validate_e2ee_messages(
        [
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "again"},
        ]
    )
