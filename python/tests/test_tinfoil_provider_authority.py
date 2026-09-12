"""Tinfoil's signed release authority is the trust anchor, not a static release pin."""

from __future__ import annotations

from copy import deepcopy

from anonrouter_confidential.measurements import pinned_measurement_policy_for
from anonrouter_confidential.verify.tinfoil import verify_tinfoil
from anonrouter_confidential.verify.types import AttestationExpectations

_HOST = "inference.tinfoil.sh"
_MODEL = "openai/gpt-oss-120b"
_NONCE = "ab" * 32
_CODE = "11" * 48
_TLS = "22" * 32


def _expectations() -> AttestationExpectations:
    policy = pinned_measurement_policy_for("tinfoil", _MODEL)
    assert policy is not None
    return AttestationExpectations(
        provider="tinfoil",
        upstream_model=_MODEL,
        endpoint_identity=_HOST,
        nonce=_NONCE,
        privacy_modality="tee",
        measurement_policy=policy,
        now_ms=1_800_000_000_000,
    )


def _document() -> dict:
    return {
        "schemaVersion": 1,
        "securityVerified": True,
        "verifier": {"name": "@tinfoilsh/verifier", "version": "99.0.0"},
        "configRepo": "tinfoilsh/confidential-model-router",
        "releaseTag": "v99.0.0",
        "releaseDigest": "33" * 32,
        "codeFingerprint": _CODE,
        "enclaveFingerprint": _CODE,
        "selectedRouterEndpoint": f"https://{_HOST}",
        "tlsPublicKey": _TLS,
        "enclaveMeasurement": {"tlsPublicKeyFingerprint": _TLS},
        "steps": {
            name: {"status": "success"}
            for name in (
                "fetchDigest",
                "verifyCode",
                "verifyEnclave",
                "compareMeasurements",
                "verifyCertificate",
            )
        },
    }


def test_future_signed_release_does_not_need_an_anonrouter_pin_update() -> None:
    verdict = verify_tinfoil(_document(), _expectations())
    assert verdict.status == "ok", verdict.reason
    assert verdict.verification_level == "sdk-verified"
    assert verdict.policy_source == "tinfoil-official-verifier+github-actions-sigstore"
    assert verdict.model_weight_identity is None


def test_wrong_repository_fails_closed() -> None:
    doc = _document()
    doc["configRepo"] = "attacker/confidential-model-router"
    verdict = verify_tinfoil(doc, _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "provider_release_authority"


def test_live_enclave_must_match_the_signed_release() -> None:
    doc = _document()
    doc["enclaveFingerprint"] = "44" * 48
    verdict = verify_tinfoil(doc, _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "code_matches_live_enclave"


def test_verification_document_must_name_the_official_verifier() -> None:
    doc = _document()
    doc["verifier"] = {"name": "lookalike", "version": "99.0.0"}
    verdict = verify_tinfoil(doc, _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "official_verifier_identity"


def test_tls_key_substitution_fails_closed() -> None:
    doc = deepcopy(_document())
    doc["enclaveMeasurement"]["tlsPublicKeyFingerprint"] = "55" * 32
    verdict = verify_tinfoil(doc, _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"
