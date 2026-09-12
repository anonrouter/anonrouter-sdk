"""Tinfoil's signed release authority is the trust anchor, not a static release pin.

The mutation cases here are the point of the file. A Tinfoil verdict is almost
entirely delegated: Tinfoil's own verifier does the cryptography and hands over a
document. What makes that safe is that every field relied on is checked against
something the document cannot choose for itself. The serving TLS key is the
clearest case, because the document reports it TWICE from one AMD-report field,
so a check comparing those two copies passes for every document ever written.

The JavaScript twin of this file is ``js/confidential/test/tinfoil-verdict.test.ts``.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from anonrouter_confidential.measurements import (
    pinned_endpoint_identity_for,
    pinned_measurement_policy_for,
)
from anonrouter_confidential.verify.tinfoil import (
    TINFOIL_ENDPOINT_IDENTITY,
    verify_tinfoil,
)
from anonrouter_confidential.verify.types import AttestationExpectations

_HOST = "inference.tinfoil.sh"
_MODEL = "openai/gpt-oss-120b"
_NONCE = "ab" * 32
_CODE = "11" * 48
_TLS = "22" * 32


def _expectations(endpoint_identity: str = _HOST) -> AttestationExpectations:
    policy = pinned_measurement_policy_for("tinfoil", _MODEL)
    assert policy is not None
    return AttestationExpectations(
        provider="tinfoil",
        upstream_model=_MODEL,
        endpoint_identity=endpoint_identity,
        nonce=_NONCE,
        privacy_modality="tee",
        measurement_policy=policy,
        now_ms=1_800_000_000_000,
    )


def _binding(**over: Any) -> dict[str, Any]:
    """What whoever opened the serving connection observed on it. Never something
    the document asserts about itself."""
    return {
        "mode": "tls-pinned",
        "endpointIdentity": _HOST,
        "observedTlsSpki": _TLS,
        "verified": True,
        **over,
    }


def _document(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schemaVersion": 1,
        "securityVerified": True,
        "verifier": {"name": "@tinfoilsh/verifier", "version": "99.0.0"},
        "configRepo": "tinfoilsh/confidential-model-router",
        "releaseTag": "v99.0.0",
        "releaseDigest": "33" * 32,
        "codeFingerprint": _CODE,
        "enclaveFingerprint": _CODE,
        "enclaveHost": f"https://{_HOST}",
        "selectedRouterEndpoint": f"https://{_HOST}",
        "tlsPublicKey": _TLS,
        "enclaveMeasurement": {"tlsPublicKeyFingerprint": _TLS},
        "transportBinding": _binding(),
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
    doc.update(over)
    return doc


def test_future_signed_release_does_not_need_an_anonrouter_pin_update() -> None:
    verdict = verify_tinfoil(_document(), _expectations())
    assert verdict.status == "ok", verdict.reason
    assert verdict.verification_level == "sdk-verified"
    assert verdict.policy_source == "tinfoil-official-verifier+github-actions-sigstore"
    assert verdict.model_weight_identity is None


def test_reports_amd_sev_snp_and_claims_nothing_about_a_gpu_or_the_weights() -> None:
    # The official verifier establishes no NVIDIA confidential-compute evidence,
    # and the document carries no model-weight digest. Reporting either would be
    # claiming a chain nobody walked.
    verdict = verify_tinfoil(_document(), _expectations())
    assert verdict.hardware_type == "amd-sev-snp"
    assert verdict.model_weight_identity is None
    assert "nvidia" not in repr(verdict.as_dict()).lower()


def test_wrong_repository_fails_closed() -> None:
    verdict = verify_tinfoil(
        _document(configRepo="attacker/confidential-model-router"), _expectations()
    )
    assert verdict.status == "failed"
    assert verdict.reason == "provider_release_authority"


def test_live_enclave_must_match_the_signed_release() -> None:
    verdict = verify_tinfoil(_document(enclaveFingerprint="44" * 48), _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "code_matches_live_enclave"


def test_verification_document_must_name_the_official_verifier() -> None:
    verdict = verify_tinfoil(
        _document(verifier={"name": "lookalike", "version": "99.0.0"}), _expectations()
    )
    assert verdict.status == "failed"
    assert verdict.reason == "official_verifier_identity"


# ---- the serving TLS key is bound to an observed connection, not to itself ----


def test_a_document_that_only_repeats_the_attested_key_is_refused() -> None:
    # The exact shape the old check accepted. Both fields are copies of one AMD
    # report field, so they agree in every document ever produced, including one
    # fabricated whole. With no observation of a real connection there is no
    # evidence about what is actually serving.
    doc = _document()
    del doc["transportBinding"]
    assert doc["tlsPublicKey"] == doc["enclaveMeasurement"]["tlsPublicKeyFingerprint"]

    verdict = verify_tinfoil(doc, _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"
    # Pinned verbatim: the JavaScript twin prints the same sentence, and a CLI
    # that explained the same refusal two different ways would be its own bug.
    failed = next(c for c in verdict.checks if c.name == "attested_key_binding")
    assert failed.detail == (
        "attested TLS key is missing, or was not confirmed by an observed "
        "pinned connection to the enclave"
    )


def test_tls_key_substitution_fails_closed() -> None:
    doc = deepcopy(_document())
    doc["enclaveMeasurement"]["tlsPublicKeyFingerprint"] = "55" * 32
    verdict = verify_tinfoil(doc, _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"


def test_a_connection_that_served_another_key_fails_closed() -> None:
    verdict = verify_tinfoil(
        _document(transportBinding=_binding(observedTlsSpki="7e" * 32)), _expectations()
    )
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"


def test_an_observation_that_did_not_verify_is_not_an_acceptance() -> None:
    verdict = verify_tinfoil(
        _document(transportBinding=_binding(verified=False)), _expectations()
    )
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"


def test_an_observation_of_another_endpoint_proves_nothing_here() -> None:
    verdict = verify_tinfoil(
        _document(transportBinding=_binding(endpointIdentity="inference.attacker.example")),
        _expectations(),
    )
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"


def test_a_transport_mode_other_than_tls_pinned_is_refused() -> None:
    verdict = verify_tinfoil(_document(transportBinding=_binding(mode="tls")), _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "attested_key_binding"


# ---- both endpoint identities are fixed to inference.tinfoil.sh --------------


def test_the_fixed_host_and_the_shipped_pin_do_not_drift_apart() -> None:
    # The verifier compares against a constant, on purpose. If the shipped policy
    # ever named a different host, every Tinfoil route would fail closed with no
    # obvious cause. Make that a build failure instead of a mystery.
    assert TINFOIL_ENDPOINT_IDENTITY == "inference.tinfoil.sh"
    assert pinned_endpoint_identity_for("tinfoil", _MODEL) == TINFOIL_ENDPOINT_IDENTITY


def test_selected_router_substitution_fails_closed() -> None:
    verdict = verify_tinfoil(
        _document(selectedRouterEndpoint="https://evil.example.com"), _expectations()
    )
    assert verdict.status == "failed"
    assert verdict.reason == "enclave_host_binding"


def test_enclave_host_substitution_fails_closed() -> None:
    # The document carries two endpoint identities. Checking only the selected
    # router left this one free to name anywhere at all.
    verdict = verify_tinfoil(_document(enclaveHost="https://evil.example.com"), _expectations())
    assert verdict.status == "failed"
    assert verdict.reason == "enclave_host_binding"


def test_the_caller_cannot_move_the_endpoint_the_document_is_graded_against() -> None:
    # Grading the document against a caller-supplied endpoint would make the
    # check a tautology from the other direction: name the attacker's host
    # everywhere and it agrees with itself. The supported host is fixed.
    doc = _document(
        enclaveHost="https://evil.example.com",
        selectedRouterEndpoint="https://evil.example.com",
        transportBinding=_binding(endpointIdentity="evil.example.com"),
    )
    verdict = verify_tinfoil(doc, _expectations(endpoint_identity="evil.example.com"))
    assert verdict.status == "failed"
    assert verdict.reason == "enclave_host_binding"
