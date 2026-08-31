"""Live-CVM validation.

Three modes, and the distinctions are the point:

    OPT-IN LIVE     ANONROUTER_LIVE_GATEWAY_ORIGIN points at a real confidential
                    deployment. These run for real: fresh nonce, real TDX quote,
                    real event log, real measurements.

    OPT-IN HARDWARE ANONROUTER_DCAP_VERIFIER_BIN additionally points at the
                    reviewed DCAP engine. The chain to Intel's roots is then
                    checked too, and the verdict may legitimately reach
                    hardware_verified.

    DEFAULT         Nothing configured, so the live cases SKIP with a stated
                    reason. They are never silently green: the readiness cases
                    still run and assert the properties that must hold BEFORE a
                    live run can mean anything.

What this file must never do is fabricate a passing live result. A synthetic
fixture cannot stand in for hardware, so with no hardware the honest output is a
skip that says so, not a green check implying a run happened.

THE NEGATIVES ARE THE POINT. A live "it verified" is nearly worthless on its own:
a verifier that returned ok for everything would produce it too. Each tamper case
below takes the SAME genuine document, changes exactly one thing, and requires the
verdict to fail on the exact check that covers it.

The gateway attestation endpoint is credential-free, content-free, and read-only,
so pointing this at a real deployment is safe: no prompt, no key, no account
identity is sent.

Mirrors ``js/confidential/test/live-cvm.test.ts``.
"""

from __future__ import annotations

import copy as copy_module
import json
import os
import secrets
import time
from typing import Any

import httpx
import pytest

from anonrouter_confidential.client import create_client
from anonrouter_confidential.gateway.binding import (
    gateway_binding_hash,
    normalize_gateway_binding,
)
from anonrouter_confidential.gateway.dcap import (
    create_anonrouter_dcap_verifier,
    resolve_dcap_verifier_binary,
)
from anonrouter_confidential.gateway.event_log import parse_event_log, replay_rtmrs
from anonrouter_confidential.gateway.policy import (
    load_gateway_policy,
    pinned_gateway_policy_for,
)
from anonrouter_confidential.gateway.verify import verify_gateway_attestation
from anonrouter_confidential.tdx import TDX_TEE_TYPE, parse_tdx_quote

LIVE_ORIGIN = os.environ.get("ANONROUTER_LIVE_GATEWAY_ORIGIN")
#: A deployment that is expected NOT to serve the confidential contract.
PUBLIC_ORIGIN = os.environ.get("ANONROUTER_LIVE_PUBLIC_ORIGIN")
ENGINE = resolve_dcap_verifier_binary().path

#: Byte offset of report_data inside a TDX v4 quote.
REPORT_DATA_OFFSET = 568
#: Byte offset of td_attributes, whose bit 0 is TUD.DEBUG.
TD_ATTRIBUTES_OFFSET = 168
RTMR0_OFFSET = 376
MR_TD_OFFSET = 184

requires_live = pytest.mark.skipif(
    not LIVE_ORIGIN,
    reason="set ANONROUTER_LIVE_GATEWAY_ORIGIN to run against a real confidential VM",
)
requires_public = pytest.mark.skipif(
    not PUBLIC_ORIGIN,
    reason="set ANONROUTER_LIVE_PUBLIC_ORIGIN to probe a non-confidential deployment",
)
requires_hardware = pytest.mark.skipif(
    not (LIVE_ORIGIN and ENGINE),
    reason="needs both ANONROUTER_LIVE_GATEWAY_ORIGIN and an installed DCAP engine",
)


def fresh_nonce() -> str:
    return secrets.token_hex(32)


#: One connection pool for the whole module. A confidential VM is a small machine
#: and a fresh TLS handshake per case is unkind to it as well as slow; the evidence
#: is bound to a fresh nonce either way, so reusing the connection changes nothing
#: about what is being proved.
_CLIENT = httpx.Client(timeout=30.0)


def fetch_live(origin: str, nonce: str, attempts: int = 3) -> dict[str, Any]:
    """Fetch one evidence document, retrying only TRANSPORT failures.

    A suite this size opens a lot of connections in a few seconds; a dropped
    handshake is a fact about the network, not about the evidence. Retrying is
    safe precisely because nothing about the verification is relaxed: the nonce
    still has to come back inside the quote. An HTTP error status is NOT retried,
    because that is the server answering.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        if attempt > 0:
            time.sleep(0.5 * attempt)
        try:
            response = _CLIENT.get(
                f"{origin}/v1/gateway/attestation",
                params={"nonce": nonce},
                headers={"accept": "application/json"},
            )
        except httpx.TransportError as exc:
            last_error = exc
            continue
        response.raise_for_status()
        body = response.json()
        assert isinstance(body, dict)
        return body
    raise AssertionError(f"could not reach {origin} in {attempts} attempts: {last_error}")


def policy_from(binding: Any, **overrides: Any) -> Any:
    """A policy pinned to the document's own identity.

    NOT A SECURITY RESULT: a policy read out of the evidence it authorizes is
    circular, and the source string says so. It exists so the CRYPTOGRAPHIC checks
    can be exercised against real hardware independently of whether the shipped pin
    is current, which is a different question with its own case below.
    """
    document = {
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
    document.update(overrides)
    return load_gateway_policy(document)


def flip_quote_byte(quote_hex: str, offset: int) -> str:
    """Flip one bit in the byte at ``offset`` of a hex-encoded quote."""
    at = offset * 2
    byte = int(quote_hex[at : at + 2], 16) ^ 0x01
    return quote_hex[:at] + f"{byte:02x}" + quote_hex[at + 2 :]


def set_debug_bit(quote_hex: str) -> str:
    """Set TUD.DEBUG, turning genuine evidence into a debug TD's evidence."""
    at = TD_ATTRIBUTES_OFFSET * 2
    byte = int(quote_hex[at : at + 2], 16) | 0x01
    return quote_hex[:at] + f"{byte:02x}" + quote_hex[at + 2 :]


def failed_check(result: Any, name: str) -> Any:
    return next(c for c in result.checks if c.name == name)


# ---- Readiness: always runs, no hardware required -----------------------------


def test_states_which_mode_the_suite_ran_in() -> None:
    # Puts the mode in the output so a skip is never ambiguous.
    if LIVE_ORIGIN:
        mode = f"LIVE against {LIVE_ORIGIN} {'WITH' if ENGINE else 'WITHOUT'} a DCAP engine"
    else:
        mode = "SKIPPED (no ANONROUTER_LIVE_GATEWAY_ORIGIN)"
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
def test_answers_two_challenges_with_two_documents() -> None:
    # A recorded document replayed to everyone would answer the case above just as
    # well. Two fresh nonces must produce two different report_data values, which
    # is only possible if the TD quoted each challenge.
    first = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    second = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    a = parse_tdx_quote(first["quote"])
    b = parse_tdx_quote(second["quote"])
    assert a is not None and b is not None
    assert a.report_data != b.report_data
    # ...while the MEASUREMENTS stay identical, because it is the same TD.
    assert a.mr_td == b.mr_td
    assert a.rtmr0 == b.rtmr0


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
        now_ms=time.time() * 1000.0,
    )
    assert result.status == "ok"
    assert result.verification_level == "provider-attested"


# ---- Live negatives: one genuine document, one change at a time ---------------


@pytest.fixture(scope="module")
def live_document() -> tuple[str, dict[str, Any], Any, Any]:
    """One genuine document, reused so each negative changes exactly one thing."""
    if not LIVE_ORIGIN:
        pytest.skip("no live origin configured")
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    binding = normalize_gateway_binding(doc["binding"])
    return nonce, doc, binding, policy_from(binding)


def verify_mutated(
    live_document: tuple[str, dict[str, Any], Any, Any],
    mutate: Any,
    **expectations: Any,
) -> Any:
    """Verify a locally modified copy of the genuine document."""
    nonce, doc, binding, policy = live_document
    modified = mutate(copy_module.deepcopy(doc))
    kwargs: dict[str, Any] = {
        "nonce": nonce,
        "origin": binding.origin,
        "policy": policy,
        "now_ms": time.time() * 1000.0,
    }
    kwargs.update(expectations)
    return verify_gateway_attestation(modified, **kwargs)


@requires_live
def test_the_unmodified_document_verifies(live_document: Any) -> None:
    # Establishes the baseline, so every failure below is caused by the change.
    assert verify_mutated(live_document, lambda d: d).status == "ok"


@requires_live
def test_replay_against_a_nonce_it_never_saw(live_document: Any) -> None:
    result = verify_mutated(live_document, lambda d: d, nonce=fresh_nonce())
    assert result.status == "failed"
    assert result.reason == "nonce_matches_request"


@requires_live
def test_wrong_origin_is_refused(live_document: Any) -> None:
    # The document belongs to whoever it names. Accepting it for another origin
    # would let one verified deployment vouch for an unverified one.
    result = verify_mutated(live_document, lambda d: d, origin="https://someone-else.example")
    assert result.status == "failed"
    assert failed_check(result, "origin_matches_connection").passed is False


@requires_live
def test_tampered_release_id_breaks_report_data(live_document: Any) -> None:
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        d["binding"]["release_id"] = "anonrouter-tee@attacker"
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "report_data_binds_binding").passed is False


@requires_live
def test_tampered_tls_fingerprint_breaks_report_data(live_document: Any) -> None:
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        d["binding"]["tls_spki_sha256"] = "ab" * 32
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "report_data_binds_binding").passed is False


@requires_live
def test_flipped_report_data_byte_breaks_the_binding(live_document: Any) -> None:
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        d["quote"] = flip_quote_byte(str(d["quote"]), REPORT_DATA_OFFSET)
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "report_data_binds_binding").passed is False


@requires_live
def test_flipped_rtmr_byte_breaks_the_replay(live_document: Any) -> None:
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        d["quote"] = flip_quote_byte(str(d["quote"]), RTMR0_OFFSET)
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "event_log_replays_rtmrs").passed is False


@requires_live
def test_debug_bit_is_fatal(live_document: Any) -> None:
    # A debug TD lets the host read and modify guest memory, so nothing measured
    # inside it is confidential. This must fail regardless of everything else.
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        d["quote"] = set_debug_bit(str(d["quote"]))
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "quote_not_debug").passed is False


@requires_live
def test_tampered_event_digest_breaks_the_replay(live_document: Any) -> None:
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        events = json.loads(str(d["event_log"]))
        events[0]["digest"] = "00" * 48
        d["event_log"] = json.dumps(events)
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "event_log_replays_rtmrs").passed is False


@requires_live
def test_rewritten_compose_hash_payload_breaks_the_replay(live_document: Any) -> None:
    # The attack this closes: take a genuine quote and its genuine log, and
    # rewrite the readable compose-hash payload to a value the client's policy
    # accepts. It fails because RTMR3 digests are DERIVED from each event's own
    # fields rather than read out of the log.
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        events = json.loads(str(d["event_log"]))
        target = next(e for e in events if e.get("event") == "compose-hash")
        # The live agent ships RTMR3 entries with an EMPTY digest precisely so the
        # verifier must derive one. Confirm that, because the argument above only
        # holds if the digest is not being read from the log.
        assert target["digest"] == ""
        target["event_payload"] = "ff" * 32
        d["event_log"] = json.dumps(events)
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "event_log_replays_rtmrs").passed is False


@requires_live
def test_supplied_digest_must_commit_to_its_payload(live_document: Any) -> None:
    # The other half. If a log supplies a digest instead of leaving it empty, the
    # verifier must still require it to agree with the payload printed beside it.
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        events = json.loads(str(d["event_log"]))
        target = next(e for e in events if e.get("event") == "compose-hash")
        target["digest"] = "ab" * 48
        d["event_log"] = json.dumps(events)
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "event_digests_commit_to_payloads").passed is False


@requires_live
def test_tampered_manifest_is_no_longer_the_measured_one(live_document: Any) -> None:
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        d["app_compose"] = f"{d['app_compose']} "
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "app_compose_matches_measurement").passed is False


@requires_live
def test_tampered_vm_config_os_image_is_caught(live_document: Any) -> None:
    # vm_config is what an auditor re-feeds to dstack-mr. A CVM that named a
    # different OS image would send them to reproduce the wrong measurements and
    # conclude the quote was forged.
    def mutate(d: dict[str, Any]) -> dict[str, Any]:
        config = json.loads(str(d["vm_config"]))
        config["os_image_hash"] = "ab" * 32
        d["vm_config"] = json.dumps(config)
        return d

    result = verify_mutated(live_document, mutate)
    assert result.status == "failed"
    assert failed_check(result, "vm_config_matches_measured_os_image").passed is False


@requires_live
def test_stale_evidence_fails_when_freshness_is_required(live_document: Any) -> None:
    nonce, doc, binding, _ = live_document
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy_from(binding, requireEvidenceExpiry=True, maxEvidenceAgeMs=1000),
        now_ms=time.time() * 1000.0 + 3_600_000,
    )
    assert result.status == "failed"
    assert failed_check(result, "evidence_recent").passed is False


@requires_live
def test_wrong_observed_certificate_is_refused(live_document: Any) -> None:
    nonce, doc, binding, _ = live_document
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy_from(binding, requireInTeeTls=True),
        now_ms=time.time() * 1000.0,
        observed_tls_spki_sha256="cd" * 32,
        observed_tls_spki_supplied=True,
    )
    assert result.status == "failed"
    assert failed_check(result, "tls_certificate_bound_to_quote").passed is False


@requires_live
def test_wrong_key_provider_is_a_different_trust_domain(live_document: Any) -> None:
    nonce, doc, binding, _ = live_document
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy_from(binding, keyProviderId="ab" * 32),
        now_ms=time.time() * 1000.0,
    )
    assert result.status == "failed"
    assert failed_check(result, "key_provider_pinned").passed is False


@requires_live
def test_wrong_platform_pin_is_refused(live_document: Any) -> None:
    nonce, doc, binding, _ = live_document
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy_from(
            binding,
            platform={
                "mrTd": ["ab" * 48],
                "mrConfigId": ["ab" * 48],
                "rtmr0": ["ab" * 48],
                "rtmr1": ["ab" * 48],
                "rtmr2": ["ab" * 48],
                "osImageHash": ["ab" * 32],
            },
        ),
        now_ms=time.time() * 1000.0,
    )
    assert result.status == "failed"
    assert failed_check(result, "platform_measurements_pinned").passed is False
    assert failed_check(result, "os_image_pinned").passed is False


# ---- Live: the shipped pin, held to the plane it names ------------------------


@requires_live
def test_the_shipped_pin_does_not_resolve_without_the_opt_in() -> None:
    assert pinned_gateway_policy_for(str(LIVE_ORIGIN)) is None


@requires_live
def test_only_policy_checks_may_fail_under_the_shipped_pin() -> None:
    # The invariant worth asserting live, and it survives a future pin refresh: a
    # stale pin must fail ONLY on the policy checks. If a structural or
    # cryptographic check ever failed against real hardware, the verifier and the
    # hardware disagree, which is a defect rather than a stale allowlist.
    entry = pinned_gateway_policy_for(str(LIVE_ORIGIN), allow_candidate=True)
    if entry is None:
        pytest.skip("this package ships no pin for the configured live origin")
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=str(LIVE_ORIGIN),
        policy=entry.policy,
        now_ms=time.time() * 1000.0,
    )
    policy_checks = {
        "app_id_pinned",
        "compose_hash_pinned",
        "release_pinned",
        "origin_pinned",
        "platform_measurements_pinned",
        "os_image_pinned",
        "key_provider_pinned",
        # Not a policy pin, but not a hardware disagreement either: the package
        # ships no engine, so this fails by construction unless one was supplied.
        "quote_signature_chain",
        "tcb_status_acceptable",
    }
    unexpected = [
        f"{c.name} ({c.detail})" if c.detail else c.name
        for c in result.checks
        if c.required and not c.passed and c.name not in policy_checks
    ]
    assert unexpected == []


# ---- Live + engine: the full chain to Intel's roots --------------------------


@requires_hardware
def test_reaches_hardware_verified_with_an_acceptable_tcb() -> None:
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    binding = normalize_gateway_binding(doc["binding"])
    policy = policy_from(binding, requireHardwareVerified=True)
    verifier = create_anonrouter_dcap_verifier().prepare(
        str(doc["quote"]),
        accepted_tcb_statuses=list(policy.acceptable_tcb_statuses),
        now_ms=time.time() * 1000.0,
    )
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy,
        now_ms=time.time() * 1000.0,
        chain_verifier=verifier,
    )
    assert result.status == "ok"
    assert result.verification_level == "hardware-verified"
    assert result.tcb_status in policy.acceptable_tcb_statuses


@requires_hardware
def test_refuses_a_tampered_quote_at_the_signature() -> None:
    # The check no amount of structural verification can make: this quote is
    # internally consistent right up to the ECDSA signature, and only the chain to
    # Intel's roots catches it.
    doc = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    tampered = flip_quote_byte(str(doc["quote"]), MR_TD_OFFSET)
    verifier = create_anonrouter_dcap_verifier().prepare(
        tampered, accepted_tcb_statuses=["UpToDate"], now_ms=time.time() * 1000.0
    )
    assert verifier.verify_chain(tampered)[0] is False


@requires_hardware
def test_a_prepared_verifier_refuses_a_different_live_quote() -> None:
    doc = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    verifier = create_anonrouter_dcap_verifier().prepare(
        str(doc["quote"]), accepted_tcb_statuses=["UpToDate"], now_ms=time.time() * 1000.0
    )
    assert verifier.verify_chain(str(doc["quote"]))[0] is True
    other = fetch_live(str(LIVE_ORIGIN), fresh_nonce())
    assert verifier.verify_chain(str(other["quote"]))[0] is False


@requires_hardware
def test_refuses_when_no_reportable_tcb_status_is_accepted() -> None:
    # The case that separates "the signature is genuine" from "this machine is safe
    # to hand data to". Both are required; neither implies the other.
    nonce = fresh_nonce()
    doc = fetch_live(str(LIVE_ORIGIN), nonce)
    binding = normalize_gateway_binding(doc["binding"])
    policy = policy_from(
        binding, requireHardwareVerified=True, acceptableTcbStatuses=["Revoked"]
    )
    verifier = create_anonrouter_dcap_verifier().prepare(
        str(doc["quote"]),
        # The engine is told the same list, so it refuses too. Both layers gate.
        accepted_tcb_statuses=list(policy.acceptable_tcb_statuses),
        now_ms=time.time() * 1000.0,
    )
    result = verify_gateway_attestation(
        doc,
        nonce=nonce,
        origin=binding.origin,
        policy=policy,
        now_ms=time.time() * 1000.0,
        chain_verifier=verifier,
    )
    assert result.status == "failed"
    assert failed_check(result, "tcb_status_acceptable").passed is False


# ---- Live: a deployment that does NOT serve the confidential contract --------


@requires_public
def test_public_origin_reports_the_route_as_absent() -> None:
    response = _CLIENT.get(
        f"{PUBLIC_ORIGIN}/v1/gateway/attestation",
        params={"nonce": fresh_nonce()},
        headers={"accept": "application/json"},
    )
    # 404 (no such route) and 503 (running, but not attestable) are the two
    # documented answers. Anything else would mean the contract exists here and
    # this test's premise is wrong.
    assert response.status_code in (404, 503)


@requires_public
def test_public_origin_verify_route_reports_unavailable() -> None:
    # "We could not look" and "we looked and it failed" call for different
    # responses. Collapsing them would hide which one an operator is in.
    policy = load_gateway_policy(
        {
            "source": "public-origin-probe",
            "version": "1",
            "origins": [str(PUBLIC_ORIGIN)],
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
    with create_client(str(PUBLIC_ORIGIN), "unused-for-gateway-verification") as client:
        verdict = client.verify_route("-", "-", gateway={"policy": policy})
    assert verdict.gateway.requested is True
    assert verdict.gateway.state == "unavailable"
    assert verdict.gateway.failed_checks == []


@requires_public
def test_no_pin_ships_for_the_public_origin() -> None:
    assert pinned_gateway_policy_for(str(PUBLIC_ORIGIN), allow_candidate=True) is None
