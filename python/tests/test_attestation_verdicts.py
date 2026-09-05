"""Verdict known-answer parity: run every case in shared/vectors/attestation.json
through the verifier and assert the whole verdict, not just its status.

The JavaScript suite loads the same file and asserts the same fields, so a verifier
change that lands in only one language fails CI. The measurement policy is NOT
carried in the vectors: each language resolves it from its own copy of the pins, so
these cases also prove both copies gate identically.
"""

from __future__ import annotations

from typing import Any

import pytest

from anonrouter_confidential import pinned_measurement_policy_for, verify_raw_evidence
from anonrouter_confidential.verify.types import AttestationExpectations


def _expectations(case: dict[str, Any]) -> AttestationExpectations:
    return AttestationExpectations(
        provider=case["provider"],
        upstream_model=case["upstreamModel"],
        endpoint_identity=case["endpointIdentity"],
        nonce=case["nonce"],
        privacy_modality=case["privacyModality"],
        measurement_policy=pinned_measurement_policy_for(case["provider"], case["upstreamModel"]),
        now_ms=case["nowMs"],
    )


def test_vectors_cover_every_verifiable_e2ee_provider(attestation_vectors: dict[str, Any]) -> None:
    providers = {case["provider"] for case in attestation_vectors["cases"]}
    assert {"venice", "chutes", "near-ai"} <= providers
    assert attestation_vectors["cases"]


def test_every_case_matches_the_recorded_verdict(attestation_vectors: dict[str, Any]) -> None:
    for case in attestation_vectors["cases"]:
        verdict = verify_raw_evidence(case["provider"], case["rawEvidence"], _expectations(case))
        expected = case["expected"]
        name = case["name"]

        assert verdict.status == expected["status"], name
        assert verdict.verification_level == expected["verificationLevel"], name
        assert verdict.reason == expected["reason"], name
        assert verdict.supports_client_opaque_e2ee == expected["supportsClientOpaqueE2ee"], name
        failed = [c.name for c in verdict.checks if c.required and not c.passed]
        assert failed == expected["failedRequiredChecks"], name
        # Advisory failures are pinned too. They do not change the status, which
        # is why they need a gate of their own: a named gap that quietly stopped
        # being reported looks exactly like a route that never had one.
        advisory = [c.name for c in verdict.checks if not c.required and not c.passed]
        assert advisory == expected["failedAdvisoryChecks"], name


def test_no_case_claims_hardware_verified(attestation_vectors: dict[str, Any]) -> None:
    for case in attestation_vectors["cases"]:
        assert case["expected"]["verificationLevel"] != "hardware-verified"


@pytest.mark.parametrize("status", ["ok", "failed"])
def test_vectors_exercise_both_outcomes(attestation_vectors: dict[str, Any], status: str) -> None:
    """A vector file that only ever passes, or only ever fails, would not prove much."""
    assert any(case["expected"]["status"] == status for case in attestation_vectors["cases"])
