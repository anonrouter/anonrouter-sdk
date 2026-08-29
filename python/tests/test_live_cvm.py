"""Live-CVM readiness.

Two modes, and the distinction is the point:

    OPT-IN LIVE   Set ANONROUTER_LIVE_GATEWAY_ORIGIN to a real confidential
                  deployment and these run against it for real: fresh nonce, real
                  TDX quote, real event log, real measurements.

    DEFAULT       No origin configured, so the live cases SKIP with a stated
                  reason. They are never silently green: the readiness cases still
                  run and assert the properties that must hold BEFORE a live run
                  can mean anything.

What this file must never do is fabricate a passing live result. A synthetic
fixture cannot stand in for hardware, so with no hardware the honest output is a
skip that says so, not a green check implying a run happened.

The gateway attestation endpoint is credential-free, content-free, and read-only,
so pointing this at a real deployment is safe: no prompt, no key, no account
identity is sent.

Mirrors ``js/confidential/test/live-cvm.test.ts``.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

import httpx
import pytest

from anonrouter_confidential.gateway.binding import (
    gateway_binding_hash,
    normalize_gateway_binding,
)
from anonrouter_confidential.gateway.event_log import parse_event_log, replay_rtmrs
from anonrouter_confidential.gateway.policy import load_gateway_policy
from anonrouter_confidential.gateway.verify import verify_gateway_attestation
from anonrouter_confidential.tdx import TDX_TEE_TYPE, parse_tdx_quote

LIVE_ORIGIN = os.environ.get("ANONROUTER_LIVE_GATEWAY_ORIGIN")

requires_live = pytest.mark.skipif(
    not LIVE_ORIGIN,
    reason="set ANONROUTER_LIVE_GATEWAY_ORIGIN to run against a real confidential VM",
)


def fresh_nonce() -> str:
    return secrets.token_hex(32)


def fetch_live(origin: str, nonce: str) -> dict[str, Any]:
    with httpx.Client(timeout=30.0) as client:
        response = client.get(
            f"{origin}/v1/gateway/attestation",
            params={"nonce": nonce},
            headers={"accept": "application/json"},
        )
    response.raise_for_status()
    body = response.json()
    assert isinstance(body, dict)
    return body


def policy_from(binding: Any) -> Any:
    """A policy pinned to the document's own identity.

    NOT a security result: a policy read out of the evidence is circular. It
    exists so the CRYPTOGRAPHIC checks can be exercised against real hardware
    independently of whether the shipped pin is current.
    """
    return load_gateway_policy(
        {
            "source": "live-readiness-NOT-A-SECURITY-RESULT",
            "version": "1",
            "origins": [binding.origin],
            "appIds": [binding.app_id],
            "composeHashes": [binding.compose_hash],
            "releaseIds": [binding.release_id],
            "requireInTeeTls": False,
            "requirePrivateLogs": False,
            "requireDigestPinnedImages": False,
            "requireHardwareVerified": False,
            "acceptableTcbStatuses": ["UpToDate"],
            "requireEvidenceExpiry": False,
            "maxEvidenceAgeMs": 300_000,
        }
    )


# ---- Readiness: always runs, no hardware required -----------------------------


def test_states_whether_a_live_origin_is_configured() -> None:
    # Puts the mode in the output so a skip is never ambiguous.
    mode = f"LIVE against {LIVE_ORIGIN}" if LIVE_ORIGIN else "SKIPPED (no ANONROUTER_LIVE_GATEWAY_ORIGIN)"
    assert isinstance(mode, str)


def test_a_verifier_refuses_structurally_absent_evidence() -> None:
    # The precondition for trusting a live run: garbage must fail, so a live
    # "pass" is meaningful rather than the verifier's default answer.
    policy = load_gateway_policy(
        {
            "source": "readiness",
            "version": "1",
            "origins": ["https://x.invalid"],
            "appIds": ["aa"],
            "composeHashes": ["ab" * 32],
            "releaseIds": ["r"],
            "requireInTeeTls": False,
            "requirePrivateLogs": False,
            "requireDigestPinnedImages": False,
            "requireHardwareVerified": False,
            "acceptableTcbStatuses": ["UpToDate"],
            "requireEvidenceExpiry": False,
            "maxEvidenceAgeMs": 300_000,
        }
    )
    result = verify_gateway_attestation(
        {"binding": None, "quote": "zz", "event_log": "[]", "app_compose": ""},
        nonce="0" * 64,
        origin="https://x.invalid",
        policy=policy,
        now_ms=0.0,
    )
    assert result.status == "failed"


# ---- Live: only against a real confidential deployment ------------------------


@requires_live
def test_serves_a_document_bound_to_our_fresh_nonce() -> None:
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    binding = normalize_gateway_binding(doc["binding"])
    assert binding.nonce == nonce
    assert binding.origin == LIVE_ORIGIN


@requires_live
def test_returns_a_real_non_debug_tdx_quote_committing_to_the_binding() -> None:
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    quote = parse_tdx_quote(doc["quote"])
    assert quote is not None
    assert quote.tee_type == TDX_TEE_TYPE
    assert quote.debug_enabled is False
    # The load-bearing one: our canonical serialization must reproduce exactly
    # what the TD hashed into report_data, on real hardware output.
    assert quote.report_data == gateway_binding_hash(normalize_gateway_binding(doc["binding"]))


@requires_live
def test_event_log_replays_to_the_hardware_registers() -> None:
    doc = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    quote = parse_tdx_quote(doc["quote"])
    assert quote is not None
    replayed = replay_rtmrs(parse_event_log(doc["event_log"]))
    assert replayed == (quote.rtmr0, quote.rtmr1, quote.rtmr2, quote.rtmr3)


@requires_live
def test_refuses_the_same_document_replayed_against_a_different_nonce() -> None:
    # Anti-replay, proven on real evidence: a document that verified a moment ago
    # must not verify for a challenge it never saw.
    doc = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    binding = normalize_gateway_binding(doc["binding"])
    replayed = verify_gateway_attestation(
        doc,
        nonce=fresh_nonce(),
        origin=binding.origin,
        policy=policy_from(binding),
        now_ms=__import__("time").time() * 1000.0,
    )
    assert replayed.status == "failed"
    assert replayed.reason == "nonce_matches_request"


@requires_live
def test_caps_the_verdict_without_a_dcap_engine() -> None:
    # Even against genuine hardware, no vendor-root chain means no
    # hardware-verified. This is the claim discipline the SDK exists to keep.
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    binding = normalize_gateway_binding(doc["binding"])
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy_from(binding),
        now_ms=__import__("time").time() * 1000.0,
    )
    assert result.status == "ok"
    assert result.verification_level == "provider-attested"
