"""TCB enforcement, evidence expiry, and the reference chain-verifier adapters.

Mirrors ``js/confidential/test/tcb-and-chain.test.ts``. The theme is that a DCAP
verdict is not a boolean: a quote can chain perfectly to Intel's roots while the
machine holding your data has known unpatched vulnerabilities, so ``verified:
True`` alone must never be enough.
"""

from __future__ import annotations

from typing import Any

from gateway_fixtures import (
    build_app_compose,
    build_synthetic_event_log,
    build_synthetic_tdx_quote,
    build_vm_config,
)

from anonrouter_confidential.gateway.binding import (
    GATEWAY_BINDING_VERSION,
    gateway_binding_hash,
)
from anonrouter_confidential.gateway.chain_verifiers import (
    DcapEngineVerdict,
    PreparedChainVerifier,
    SubprocessChainVerifier,
    parse_engine_verdict,
)
from anonrouter_confidential.gateway.policy import (
    GatewayMeasurementPolicy,
    load_gateway_policy,
)
from anonrouter_confidential.gateway.verify import verify_gateway_attestation

NONCE = "9" * 64
ORIGIN = "https://tee.anonrouter.ai"
APP_ID = "0123456789abcdef0123456789abcdef01234567"
INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98"
RELEASE_ID = "anonrouter-tee@c7b32e0"
NOW = 1_760_000_000_000.0
MANIFEST, COMPOSE_HASH = build_app_compose()

_OMIT = object()


def policy(**overrides: Any) -> GatewayMeasurementPolicy:
    doc: dict[str, Any] = {
        "source": "anonrouter-sdk@test",
        "version": "1",
        "origins": [ORIGIN],
        "appIds": [APP_ID],
        "composeHashes": [COMPOSE_HASH],
        "releaseIds": [RELEASE_ID],
        "requireInTeeTls": False,
        "requirePrivateLogs": True,
        "requireDigestPinnedImages": True,
        "requireHardwareVerified": False,
        "acceptableTcbStatuses": ["UpToDate"],
        "requireEvidenceExpiry": False,
        "maxEvidenceAgeMs": 300_000,
    }
    doc.update(overrides)
    return load_gateway_policy(doc)


def evidence(issued_at_ms: Any = NOW - 500) -> dict[str, Any]:
    """``issued_at_ms=_OMIT`` omits the field, which is a different case from a
    stale timestamp and has to be reachable to be tested."""
    binding = {
        "v": GATEWAY_BINDING_VERSION,
        "nonce": NONCE,
        "app_id": APP_ID,
        "instance_id": INSTANCE_ID,
        "compose_hash": COMPOSE_HASH,
        "release_id": RELEASE_ID,
        "origin": ORIGIN,
        "key_alg": "x25519",
        "public_key": "ab" * 32,
        "transport": "gateway-tls",
        "tls_spki_sha256": None,
    }
    log = build_synthetic_event_log(
        app_id=APP_ID, compose_hash=COMPOSE_HASH, instance_id=INSTANCE_ID
    )
    doc: dict[str, Any] = {
        "binding": binding,
        "quote": build_synthetic_tdx_quote(
            report_data_hex=gateway_binding_hash(binding),
            rtmr0=log.rtmr0,
            rtmr1=log.rtmr1,
            rtmr2=log.rtmr2,
            rtmr3=log.rtmr3,
        ),
        "event_log": log.as_json(),
        "app_compose": MANIFEST,
        "vm_config": build_vm_config(),
    }
    if issued_at_ms is not _OMIT:
        doc["issued_at_ms"] = issued_at_ms
    return doc


class _Chain:
    implementation = "test"

    def __init__(self, verified: bool, tcb: str | None) -> None:
        self._v, self._t = verified, tcb

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None]:
        return self._v, self._t


def verify(chain: Any = None, issued_at: Any = NOW - 500, **policy_overrides: Any) -> Any:
    return verify_gateway_attestation(
        evidence(issued_at),
        nonce=NONCE,
        origin=ORIGIN,
        policy=policy(**policy_overrides),
        now_ms=NOW,
        chain_verifier=chain,
    )


def named(result: Any, name: str) -> Any:
    entry = next((c for c in result.checks if c.name == name), None)
    assert entry is not None, f"check {name} missing"
    return entry


# ---- TCB ---------------------------------------------------------------------


def test_accepts_a_verified_quote_with_an_accepted_tcb() -> None:
    r = verify(_Chain(True, "UpToDate"))
    assert r.status == "ok"
    assert r.verification_level == "hardware-verified"


def test_refuses_a_verified_quote_whose_tcb_is_out_of_date() -> None:
    # The whole point: the signature chained fine, but the platform holding the
    # data has known unpatched vulnerabilities.
    r = verify(_Chain(True, "OutOfDate"))
    assert r.status == "failed"
    assert r.reason == "tcb_status_acceptable"
    assert named(r, "quote_signature_chain").passed is True


def test_refuses_a_verifier_that_reports_no_tcb_status() -> None:
    r = verify(_Chain(True, None))
    assert r.status == "failed"
    assert r.reason == "tcb_status_acceptable"
    assert "no TCB status" in (named(r, "tcb_status_acceptable").detail or "")


def test_honours_a_widened_accepted_list() -> None:
    r = verify(
        _Chain(True, "SWHardeningNeeded"),
        acceptableTcbStatuses=["UpToDate", "SWHardeningNeeded"],
    )
    assert r.status == "ok"
    assert r.verification_level == "hardware-verified"


def test_compares_tcb_status_case_insensitively() -> None:
    assert verify(_Chain(True, "uptodate")).status == "ok"


def test_records_the_tcb_check_even_with_no_verifier() -> None:
    r = verify(None)
    entry = named(r, "tcb_status_acceptable")
    assert entry.passed is False
    assert entry.required is False
    assert r.status == "ok"
    assert r.verification_level == "provider-attested"


def test_tcb_check_is_required_when_hardware_verification_is() -> None:
    r = verify(None, requireHardwareVerified=True)
    assert r.status == "failed"
    assert named(r, "tcb_status_acceptable").required is True


# ---- expiry ------------------------------------------------------------------


def test_expiry_is_advisory_by_default() -> None:
    assert verify(None, issued_at=NOW - 500).status == "ok"


def test_fails_a_stale_document_when_expiry_is_required() -> None:
    r = verify(None, issued_at=NOW - 10 * 60_000, requireEvidenceExpiry=True)
    assert r.status == "failed"
    assert r.reason == "evidence_recent"


def test_fails_a_document_with_no_timestamp_when_expiry_is_required() -> None:
    # "Cannot be aged" must not read as "fresh enough".
    r = verify(None, issued_at=_OMIT, requireEvidenceExpiry=True)
    assert r.status == "failed"
    assert r.reason == "evidence_recent"
    assert named(r, "evidence_recent").detail == "no issued_at_ms"


def test_rejects_a_future_dated_document() -> None:
    r = verify(None, issued_at=NOW + 10 * 60_000, requireEvidenceExpiry=True)
    assert r.status == "failed"
    assert r.reason == "evidence_recent"


# ---- prepared verifier binding -----------------------------------------------


def test_prepared_verifier_refuses_a_quote_it_was_not_prepared_for() -> None:
    v = PreparedChainVerifier("aabb", DcapEngineVerdict(True, "UpToDate"), "test")
    assert v.verify_chain("aabb") == (True, "UpToDate")
    assert v.verify_chain("ccdd")[0] is False


def test_prepared_verifier_matches_case_insensitively() -> None:
    v = PreparedChainVerifier("AABB", DcapEngineVerdict(True, None), "test")
    assert v.verify_chain("aabb")[0] is True


def test_prepared_verifier_passes_a_negative_verdict_through() -> None:
    v = PreparedChainVerifier("aabb", DcapEngineVerdict(False, None, "bad chain"), "test")
    assert v.verify_chain("aabb")[0] is False


# ---- engine output parsing ---------------------------------------------------


def test_rejects_a_non_boolean_verified_field() -> None:
    # Coercing a truthy string would invent a pass out of noise.
    assert parse_engine_verdict('{"verified":"yes","tcbStatus":"UpToDate"}') is None
    assert parse_engine_verdict('{"tcbStatus":"UpToDate"}') is None


def test_rejects_non_json_and_oversized_output() -> None:
    assert parse_engine_verdict("not json") is None
    assert parse_engine_verdict("") is None
    assert parse_engine_verdict("x" * (256 * 1024 + 1)) is None


def test_accepts_a_well_formed_verdict() -> None:
    v = parse_engine_verdict('{"verified":true,"tcbStatus":"UpToDate"}')
    assert v is not None
    assert v.verified is True
    assert v.tcb_status == "UpToDate"


# ---- subprocess adapter fails closed -----------------------------------------


def test_missing_binary_is_not_verified() -> None:
    adapter = SubprocessChainVerifier("/nonexistent/dcap-verifier-xyz")
    assert adapter.prepare("aabbccdd").verify_chain("aabbccdd")[0] is False


def test_non_json_output_is_not_verified() -> None:
    adapter = SubprocessChainVerifier("/bin/echo", args=["not json at all"])
    assert adapter.prepare("aabbccdd").verify_chain("aabbccdd")[0] is False


def test_malformed_quote_is_refused_before_spawning() -> None:
    adapter = SubprocessChainVerifier("/bin/echo", args=['{"verified":true}'])
    assert adapter.prepare("not-hex").verify_chain("not-hex")[0] is False


def test_well_formed_positive_verdict_is_accepted() -> None:
    adapter = SubprocessChainVerifier("/bin/echo", args=['{"verified":true,"tcbStatus":"UpToDate"}'])
    assert adapter.prepare("aabbccdd").verify_chain("aabbccdd") == (True, "UpToDate")


def test_engine_that_answers_without_draining_stdin_is_accepted() -> None:
    """Mirrors the JavaScript case of the same name.

    An engine that prints its verdict and exits without reading stdin closes the
    pipe while the quote is still being written. What decides the outcome is the
    verdict on stdout, not the write. The child closes fd 0 explicitly and the
    quote is larger than a pipe buffer, so the write cannot quietly succeed.
    """
    big_quote = "ab" * 100_000
    adapter = SubprocessChainVerifier(
        "/bin/sh",
        args=["-c", """exec 0<&-; printf '%s' '{"verified":true,"tcbStatus":"UpToDate"}'"""],
    )
    assert adapter.prepare(big_quote).verify_chain(big_quote) == (True, "UpToDate")


def test_engine_pass_still_refused_when_policy_rejects_the_tcb() -> None:
    # End to end: engine says verified/OutOfDate, policy accepts only UpToDate.
    adapter = SubprocessChainVerifier(
        "/bin/echo", args=['{"verified":true,"tcbStatus":"OutOfDate"}']
    )
    doc = evidence()
    verifier = adapter.prepare(doc["quote"])
    r = verify_gateway_attestation(
        doc, nonce=NONCE, origin=ORIGIN, policy=policy(), now_ms=NOW, chain_verifier=verifier
    )
    assert r.status == "failed"
    assert r.reason == "tcb_status_acceptable"
