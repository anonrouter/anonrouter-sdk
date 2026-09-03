"""What a Venice route that attests LESS than the others should be told about.

Mirrors ``js/confidential/test/venice-nested-attestation.test.ts`` case for case.

THE LIVE CASE THIS COMES FROM. Three of Venice's nine E2EE routes
(``deepseek/deepseek-v4-flash``, ``qwen/qwen-3.6-35b-a3b-fp8``, ``z-ai/glm-5.1``)
return a well-formed quote, a real signing key and a live nonce -- and an EMPTY
``attestation`` object. The other six populate it. Measured six times each
against production; the split is stable and does not move with load.

Two required checks fail, and they SHOULD: a binding nobody stated is a binding
that did not hold. Neither check is relaxed here. This file keeps them failing
while making them say why, because "did not match" and "carried nothing" call
for opposite responses.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anonrouter_confidential.crypto.venice import eth_address_from_pub
from anonrouter_confidential.verify import verify_raw_evidence
from anonrouter_confidential.verify.types import AttestationExpectations

_NONCE = "ab" * 32
_UPSTREAM = "e2ee-deepseek-v4-flash"

_PRIV = ec.derive_private_key(
    0x9911AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556677, ec.SECP256K1()
)
_PUB_HEX = _PRIV.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
_ADDRESS = eth_address_from_pub(_PUB_HEX)
_REPORT_DATA = (bytes.fromhex(_ADDRESS[2:]) + bytes(12) + bytes.fromhex(_NONCE)).hex()

_COMPLETE: dict[str, Any] = {
    "report_data": _REPORT_DATA,
    "evidence": {"quote_report_data": _REPORT_DATA},
    "workload_keyset": {
        "e2ee_public_keys": [
            {"algo": "secp256k1-aes-256-gcm-hkdf-sha256", "public_key": _PUB_HEX}
        ]
    },
}

_ABSENT = object()


def _quote_hex(report_data_hex: str) -> str:
    buf = bytearray(632)
    buf[0:2] = (4).to_bytes(2, "little")
    buf[4:8] = (0x81).to_bytes(4, "little")
    buf[184:232] = bytes(range(48))
    buf[568:632] = bytes.fromhex(report_data_hex)
    return buf.hex()


def _evidence(nested: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "intel_quote": _quote_hex(_REPORT_DATA),
        "nvidia_payload": "gpu-evidence",
        "nonce": _NONCE,
        "model": _UPSTREAM,
        "signing_address": _ADDRESS,
        "signing_algo": "ecdsa",
        "signing_public_key": _PUB_HEX,
    }
    if nested is not _ABSENT:
        payload["attestation"] = nested
    return payload


def _verdict(nested: Any):
    return verify_raw_evidence(
        "venice",
        _evidence(nested),
        AttestationExpectations(
            provider="venice",
            canonical_model=_UPSTREAM,
            upstream_model=_UPSTREAM,
            route_id=f"venice/{_UPSTREAM}",
            endpoint_identity="venice",
            nonce=_NONCE,
            privacy_modality="e2ee",
        ),
    )


def _detail(verdict: Any, name: str) -> str:
    for c in verdict.checks:
        if c.name == name:
            return c.detail or ""
    return ""


def test_complete_nested_attestation_verifies() -> None:
    # THE POSITIVE CONTROL. Without it, every refusal below could equally mean
    # the fixture is broken, and the suite would measure nothing.
    verdict = _verdict(_COMPLETE)
    assert verdict.status == "ok"
    assert [c.name for c in verdict.checks if c.required and not c.passed] == []


def test_empty_nested_attestation_still_refuses_both_bindings() -> None:
    verdict = _verdict({})
    assert verdict.status == "failed"
    failed = [c.name for c in verdict.checks if c.required and not c.passed]
    assert "reported_quote_binding" in failed
    assert "workload_keyset_binding" in failed


def test_empty_nested_attestation_says_absent_not_wrong() -> None:
    verdict = _verdict({})
    assert "carried no nested attestation document" in _detail(verdict, "reported_quote_binding")
    assert "attests no workload keyset" in _detail(verdict, "workload_keyset_binding")
    assert "did not match" not in _detail(verdict, "reported_quote_binding")


def test_missing_attestation_key_reads_the_same_as_empty() -> None:
    verdict = _verdict(_ABSENT)
    assert verdict.status == "failed"
    assert "carried no nested attestation document" in _detail(verdict, "reported_quote_binding")


def test_disagreeing_report_data_says_did_not_match() -> None:
    verdict = _verdict({**_COMPLETE, "report_data": "cd" * 64})
    assert verdict.status == "failed"
    assert "did not match" in _detail(verdict, "reported_quote_binding")
    assert "carried no nested" not in _detail(verdict, "reported_quote_binding")


def test_document_that_omits_report_data_is_named_separately() -> None:
    without = {k: v for k, v in _COMPLETE.items() if k != "report_data"}
    verdict = _verdict(without)
    assert verdict.status == "failed"
    assert "omits report_data" in _detail(verdict, "reported_quote_binding")


def test_keyset_present_without_the_signing_key_is_named_separately() -> None:
    verdict = _verdict({
        **_COMPLETE,
        "workload_keyset": {
            "e2ee_public_keys": [
                {"algo": "secp256k1-aes-256-gcm-hkdf-sha256", "public_key": "04" + "11" * 64}
            ]
        },
    })
    assert verdict.status == "failed"
    assert "does not contain the signing key" in _detail(verdict, "workload_keyset_binding")
    assert "attests no workload keyset" not in _detail(verdict, "workload_keyset_binding")


def test_right_key_under_the_wrong_algorithm_is_refused() -> None:
    # The algorithm is part of the binding: the same bytes used for a different
    # scheme are not the key this route's encryption is bound to.
    verdict = _verdict({
        **_COMPLETE,
        "workload_keyset": {
            "e2ee_public_keys": [{"algo": "x25519-aes-256-gcm-hkdf-sha256", "public_key": _PUB_HEX}]
        },
    })
    assert verdict.status == "failed"
    assert "does not contain the signing key" in _detail(verdict, "workload_keyset_binding")
