"""Fail-closed acceptance tests for hop 1: AnonRouter's own confidential plane.

Every test starts from a document that verifies, then breaks exactly one thing and
asserts the specific required check that catches it. A verifier that silently
tolerated any of these would let a non-attested data plane pass as attested.

Mirrors ``js/confidential/test/gateway-verify.test.ts`` case for case, so a gap in
one language shows up as a missing test in the other.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from gateway_fixtures import (
    OFF_MR_TD,
    OFF_RTMR0,
    SYNTHETIC_MR_CONFIG_ID,
    SYNTHETIC_OS_IMAGE_HASH,
    build_app_compose,
    build_synthetic_event_log,
    build_synthetic_tdx_quote,
    build_vm_config,
    quote_register,
    rtmr3_event,
    rtmr3_event_v2,
    rtmr3_event_with_digest,
)

from anonrouter_confidential.gateway.binding import (
    GATEWAY_BINDING_VERSION,
    gateway_binding_hash,
)
from anonrouter_confidential.gateway.event_log import (
    replay_register,
    rtmr3_event_digest,
)
from anonrouter_confidential.gateway.policy import (
    GatewayMeasurementPolicy,
    load_gateway_policy,
)
from anonrouter_confidential.gateway.verify import (
    GatewayVerificationResult,
    verify_gateway_attestation,
)

NONCE = "9" * 64
ORIGIN = "https://tee.anonrouter.ai"
APP_ID = "0123456789abcdef0123456789abcdef01234567"
INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98"
RELEASE_ID = "anonrouter-tee@c7b32e0"
PUBLIC_KEY = "ab" * 32
TLS_SPKI = "11" * 32
NOW = 1_760_000_000_000.0

MANIFEST, COMPOSE_HASH = build_app_compose()


def policy(**overrides: Any) -> GatewayMeasurementPolicy:
    base = load_gateway_policy(
        {
            "source": "anonrouter-sdk@test",
            "version": "2026.08.29",
            "origins": [ORIGIN],
            "appIds": [APP_ID],
            "composeHashes": [COMPOSE_HASH],
            "releaseIds": [RELEASE_ID],
            "requireInTeeTls": False,
            "requirePrivateLogs": True,
            "requireDigestPinnedImages": True,
            "requireHardwareVerified": False,
            "maxEvidenceAgeMs": 300_000,
        }
    )
    return replace(base, **overrides) if overrides else base


def binding(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "v": GATEWAY_BINDING_VERSION,
        "nonce": NONCE,
        "app_id": APP_ID,
        "instance_id": INSTANCE_ID,
        "compose_hash": COMPOSE_HASH,
        "release_id": RELEASE_ID,
        "origin": ORIGIN,
        "key_alg": "x25519",
        "public_key": PUBLIC_KEY,
        "transport": "gateway-tls",
        "tls_spki_sha256": None,
    }
    value.update(overrides)
    return value


def evidence(
    *,
    value: dict[str, Any] | None = None,
    manifest: str | None = None,
    quote_report_data: str | None = None,
    debug: bool = False,
    tee_type: int | None = None,
    extra_rtmr3: list[Any] | None = None,
    key_provider_id: str | None = None,
    compose_hash_event_payload: str | None = None,
    tamper_compose_event_payload: bool = False,
    break_rtmr3: bool = False,
    mr_config_id: str | None = None,
    measured_os_image_hash: str | None = None,
    vm_config: str | None = "",
    event_log: Any = None,
) -> dict[str, Any]:
    value = value if value is not None else binding()
    log = build_synthetic_event_log(
        app_id=APP_ID,
        compose_hash=compose_hash_event_payload or str(value["compose_hash"]),
        instance_id=str(value["instance_id"]),
        key_provider_id=key_provider_id,
        os_image_hash=measured_os_image_hash,
        extra_rtmr3=extra_rtmr3,
    )

    def tamper(entry: Any) -> Any:
        if not tamper_compose_event_payload or entry.event != "compose-hash":
            return entry
        # Keep the measured digest, rewrite only the readable payload. This is the
        # attack the digest-recomputation check exists to stop.
        return replace(entry, event_payload="c" * 64)

    doc: dict[str, Any] = {
        "binding": value,
        "quote": build_synthetic_tdx_quote(
            report_data_hex=quote_report_data or gateway_binding_hash(value),
            rtmr0=log.rtmr0,
            rtmr1=log.rtmr1,
            rtmr2=log.rtmr2,
            rtmr3="f" * 96 if break_rtmr3 else log.rtmr3,
            mr_config_id=mr_config_id or SYNTHETIC_MR_CONFIG_ID,
            debug=debug,
            tee_type=tee_type if tee_type is not None else 0x00000081,
        ),
        "event_log": event_log if event_log is not None else log.as_json(tamper),
        "app_compose": manifest if manifest is not None else MANIFEST,
        "issued_at_ms": NOW - 500,
    }
    if vm_config is not None:
        doc["vm_config"] = vm_config or build_vm_config(measured_os_image_hash or SYNTHETIC_OS_IMAGE_HASH)
    return doc


def platform_policy(**overrides: Any) -> GatewayMeasurementPolicy:
    quote = evidence()["quote"]
    platform = {
        "mrTd": [quote_register(quote, OFF_MR_TD)],
        "mrConfigId": [SYNTHETIC_MR_CONFIG_ID],
        "rtmr0": [quote_register(quote, OFF_RTMR0)],
        "rtmr1": [quote_register(quote, OFF_RTMR0 + 48)],
        "rtmr2": [quote_register(quote, OFF_RTMR0 + 96)],
        "osImageHash": [SYNTHETIC_OS_IMAGE_HASH],
    }
    platform.update(overrides)
    return load_gateway_policy(
        {
            "source": "anonrouter-sdk@test",
            "version": "2026.08.29",
            "origins": [ORIGIN],
            "appIds": [APP_ID],
            "composeHashes": [COMPOSE_HASH],
            "releaseIds": [RELEASE_ID],
            "platform": platform,
            "requireInTeeTls": False,
            "requirePrivateLogs": True,
            "requireDigestPinnedImages": True,
            "requireHardwareVerified": False,
            "maxEvidenceAgeMs": 300_000,
        }
    )


def verify(doc: dict[str, Any], **kwargs: Any) -> GatewayVerificationResult:
    params: dict[str, Any] = {
        "nonce": NONCE,
        "origin": ORIGIN,
        "policy": policy(),
        "now_ms": NOW,
    }
    params.update(kwargs)
    return verify_gateway_attestation(doc, **params)


def named_check(result: GatewayVerificationResult, name: str) -> Any:
    entry = next((c for c in result.checks if c.name == name), None)
    assert entry is not None, f"check {name} missing"
    return entry


class _PassingChain:
    implementation = "test-dcap"

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None]:
        return True, "UpToDate"


class _RejectingChain:
    implementation = "test-dcap"

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None]:
        return False, "OutOfDate"


def test_accepts_a_well_formed_document_capped_at_provider_attested() -> None:
    result = verify(evidence())
    assert result.reason is None
    assert result.status == "ok"
    # No DCAP chain verifier was supplied, so hardware-verified must NOT appear.
    assert result.verification_level == "provider-attested"
    assert result.app_compose is not None
    assert result.app_compose.public_logs is False
    assert all(i.digest_pinned for i in result.app_compose.images)
    assert result.binding is not None
    assert result.binding.origin == ORIGIN


def test_hardware_verified_only_when_a_chain_verifier_passes() -> None:
    ok = verify(evidence(), chain_verifier=_PassingChain())
    assert ok.verification_level == "hardware-verified"
    assert ok.tcb_status == "UpToDate"

    bad = verify(evidence(), chain_verifier=_RejectingChain())
    assert bad.status == "failed"
    assert bad.reason == "quote_signature_chain"


def test_fails_closed_when_policy_demands_hardware_and_no_engine_is_wired() -> None:
    # This package ships no DCAP engine, so a requireHardwareVerified policy must
    # fail loudly rather than quietly accepting at provider-attested.
    result = verify(evidence(), policy=policy(require_hardware_verified=True))
    assert result.status == "failed"
    assert result.reason == "quote_signature_chain"
    assert "no DCAP chain verifier" in (named_check(result, "quote_signature_chain").detail or "")


# ---- binding integrity -------------------------------------------------------


def test_rejects_report_data_that_does_not_bind_the_binding() -> None:
    result = verify(evidence(quote_report_data="0" * 128))
    assert result.status == "failed"
    assert result.reason == "report_data_binds_binding"


def test_rejects_a_malformed_binding_before_hashing() -> None:
    doc = evidence()
    doc["binding"] = {**binding(), "surprise": True}
    result = verify(doc)
    assert result.status == "failed"
    assert result.reason == "binding_wellformed"


def test_rejects_a_quote_bound_to_another_nonce() -> None:
    result = verify(evidence(value=binding(nonce="1" * 64)))
    assert result.status == "failed"
    assert result.reason == "nonce_matches_request"


def test_rejects_a_quote_bound_to_another_origin() -> None:
    result = verify(
        evidence(value=binding(origin="https://evil.example")),
        policy=policy(origins=[ORIGIN, "https://evil.example"]),
    )
    assert result.status == "failed"
    assert result.reason == "origin_matches_connection"


# ---- quote structure ---------------------------------------------------------


def test_rejects_an_unparseable_quote() -> None:
    doc = evidence()
    doc["quote"] = "not-a-quote"
    result = verify(doc)
    assert result.status == "failed"
    assert result.reason == "quote_parsed"


def test_rejects_a_non_tdx_tee_type() -> None:
    result = verify(evidence(tee_type=0))
    assert result.status == "failed"
    assert result.reason == "quote_is_tdx"


def test_rejects_a_debug_td() -> None:
    result = verify(evidence(debug=True))
    assert result.status == "failed"
    assert result.reason == "quote_not_debug"


# ---- event log ---------------------------------------------------------------


def test_rejects_a_log_that_does_not_replay() -> None:
    result = verify(evidence(break_rtmr3=True))
    assert result.status == "failed"
    assert result.reason == "event_log_replays_rtmrs"


def test_rejects_a_rewritten_compose_hash_payload() -> None:
    # The genuine quote and genuine digests are untouched; only the readable
    # payload beside them was rewritten. Digest recomputation is what catches it.
    result = verify(evidence(tamper_compose_event_payload=True))
    assert result.status == "failed"
    assert result.reason in ("event_digests_commit_to_payloads", "event_log_replays_rtmrs")


def test_rejects_a_compose_hash_the_hardware_never_measured() -> None:
    result = verify(evidence(compose_hash_event_payload="a" * 64))
    assert result.status == "failed"
    assert result.reason == "compose_hash_measured_in_rtmr3"


def test_rejects_an_unparseable_log_rather_than_treating_it_as_absent() -> None:
    result = verify(evidence(event_log="{not json"))
    assert result.status == "failed"
    assert result.reason == "event_log_replays_rtmrs"


def test_rejects_a_duplicated_compose_hash_event() -> None:
    result = verify(evidence(extra_rtmr3=[rtmr3_event("compose-hash", "b" * 64)]))
    assert result.status == "failed"


def test_accepts_a_v2_event_that_publishes_its_preimage() -> None:
    log = build_synthetic_event_log(
        app_id=APP_ID, compose_hash=COMPOSE_HASH, instance_id=INSTANCE_ID
    )
    # A V2 entry's digest is SHA-384 of its published preimage, not the V1
    # concatenation, so RTMR3 has to be replayed over the V2 digests.
    v2_events = [
        rtmr3_event_v2(e.event, e.event_payload, e.event_type) if e.imr == 3 and e.event else e
        for e in log.events
    ]
    rtmr3 = replay_register(
        [rtmr3_event_digest(e) or "ff" * 48 for e in v2_events if e.imr == 3]
    )
    value = binding()
    log_v2 = replace(log, events=v2_events, rtmr3=rtmr3)
    result = verify(
        {
            "binding": value,
            "quote": build_synthetic_tdx_quote(
                report_data_hex=gateway_binding_hash(value),
                rtmr0=log.rtmr0,
                rtmr1=log.rtmr1,
                rtmr2=log.rtmr2,
                rtmr3=rtmr3,
            ),
            "event_log": log_v2.as_json(),
            "app_compose": MANIFEST,
            "issued_at_ms": NOW - 500,
            "vm_config": build_vm_config(),
        }
    )
    assert result.reason is None
    assert result.status == "ok"


def test_a_v1_event_digest_is_deterministic() -> None:
    derived = rtmr3_event_with_digest("app-id", APP_ID)
    assert len(derived.digest) == 96
    assert derived.digest == rtmr3_event_with_digest("app-id", APP_ID).digest


# ---- app-compose manifest ----------------------------------------------------


def test_rejects_a_manifest_that_is_not_the_measured_one() -> None:
    other_manifest, _ = build_app_compose(name="something-else")
    result = verify(evidence(manifest=other_manifest))
    assert result.status == "failed"
    assert result.reason == "app_compose_matches_measurement"


def test_rejects_public_logs_when_the_policy_requires_them_off() -> None:
    loud_manifest, loud_hash = build_app_compose(public_logs=True)
    result = verify(
        evidence(value=binding(compose_hash=loud_hash), manifest=loud_manifest),
        policy=policy(compose_hashes=[loud_hash]),
    )
    assert result.status == "failed"
    assert result.reason == "compose_public_logs_disabled"


def test_rejects_an_image_that_is_not_digest_pinned() -> None:
    floating_manifest, floating_hash = build_app_compose(
        docker_compose_file="services:\n  relay:\n    image: ghcr.io/example/anonrouter:latest"
    )
    result = verify(
        evidence(value=binding(compose_hash=floating_hash), manifest=floating_manifest),
        policy=policy(compose_hashes=[floating_hash]),
    )
    assert result.status == "failed"
    assert result.reason == "compose_images_digest_pinned"


# ---- locally pinned identity -------------------------------------------------


def test_rejects_an_app_id_not_on_the_allowlist() -> None:
    result = verify(evidence(), policy=policy(app_ids=["dead" * 10]))
    assert result.status == "failed"
    assert result.reason == "app_id_pinned"


def test_rejects_a_compose_hash_not_on_the_allowlist() -> None:
    result = verify(evidence(), policy=policy(compose_hashes=["ab" * 32]))
    assert result.status == "failed"
    assert result.reason == "compose_hash_pinned"


def test_rejects_an_unreviewed_release() -> None:
    result = verify(evidence(), policy=policy(release_ids=["anonrouter-tee@somethingelse"]))
    assert result.status == "failed"
    assert result.reason == "release_pinned"


def test_rejects_an_origin_the_policy_does_not_authorize() -> None:
    result = verify(evidence(), policy=policy(origins=["https://other.anonrouter.ai"]))
    assert result.status == "failed"
    assert result.reason == "origin_pinned"


def test_pins_the_key_provider() -> None:
    pinned = policy(key_provider_id="aa" * 32)
    wrong = verify(evidence(), policy=pinned)
    assert wrong.status == "failed"
    assert wrong.reason == "key_provider_pinned"

    right = verify(evidence(key_provider_id="aa" * 32), policy=pinned)
    assert right.status == "ok"


def test_an_unpinned_key_provider_is_a_visible_gap_not_a_pass() -> None:
    entry = named_check(verify(evidence()), "key_provider_pinned")
    assert entry.passed is False
    assert entry.required is False
    assert "policy pins no key provider" in (entry.detail or "")


def test_pins_the_platform_stack() -> None:
    assert verify(evidence(), policy=platform_policy()).status == "ok"
    result = verify(evidence(), policy=platform_policy(rtmr0=["cc" * 48]))
    assert result.status == "failed"
    assert result.reason == "platform_measurements_pinned"


def test_pins_the_os_image_separately() -> None:
    result = verify(evidence(), policy=platform_policy(osImageHash=["ee" * 32]))
    assert result.status == "failed"
    assert result.reason == "os_image_pinned"


# ---- vm_config anchoring -----------------------------------------------------


def test_rejects_a_vm_config_naming_an_unmeasured_os_image() -> None:
    result = verify(evidence(vm_config=build_vm_config("cc" * 32)))
    assert result.status == "failed"
    assert result.reason == "vm_config_matches_measured_os_image"


def test_a_missing_vm_config_is_advisory_not_a_pass() -> None:
    result = verify(evidence(vm_config=None))
    assert result.status == "ok"
    entry = named_check(result, "vm_config_matches_measured_os_image")
    assert entry.passed is False
    assert entry.required is False
    assert "unanchored" in (entry.detail or "")


# ---- transport binding -------------------------------------------------------


def test_fails_closed_on_gateway_tls_when_in_tee_tls_is_required() -> None:
    result = verify(evidence(), policy=policy(require_in_tee_tls=True))
    assert result.status == "failed"
    assert result.reason == "transport_terminates_in_tee"


def test_binds_the_observed_certificate_to_the_quote() -> None:
    in_tee = binding(transport="in-tee-tls", tls_spki_sha256=TLS_SPKI)
    strict = policy(require_in_tee_tls=True)

    matched = verify(
        evidence(value=in_tee),
        policy=strict,
        observed_tls_spki_sha256=TLS_SPKI,
        observed_tls_spki_supplied=True,
    )
    assert matched.reason is None
    assert matched.status == "ok"

    mismatched = verify(
        evidence(value=in_tee),
        policy=strict,
        observed_tls_spki_sha256="22" * 32,
        observed_tls_spki_supplied=True,
    )
    assert mismatched.status == "failed"
    assert mismatched.reason == "tls_certificate_bound_to_quote"


def test_an_unobservable_certificate_is_a_named_gap() -> None:
    in_tee = binding(transport="in-tee-tls", tls_spki_sha256=TLS_SPKI)
    result = verify(evidence(value=in_tee), policy=policy(require_in_tee_tls=True))
    # Still ok, because the check is advisory when the caller cannot observe, but
    # the gap is named rather than assumed away.
    assert result.status == "ok"
    entry = named_check(result, "tls_certificate_bound_to_quote")
    assert entry.passed is False
    assert entry.required is False
    assert "did not observe" in (entry.detail or "")


def test_gateway_tls_is_an_advisory_weakness_when_tolerated() -> None:
    entry = named_check(verify(evidence()), "transport_terminates_in_tee")
    assert entry.passed is False
    assert entry.required is False
    assert "platform gateway" in (entry.detail or "")


# ---- hostile input -----------------------------------------------------------


def test_never_raises_on_hostile_input() -> None:
    hostile: list[Any] = [
        None,
        {},
        {"binding": None, "quote": None, "event_log": None, "app_compose": None},
        {"binding": [], "quote": 1, "event_log": {}, "app_compose": 2},
        {"binding": binding(), "quote": "zz", "event_log": "[]", "app_compose": ""},
    ]
    for doc in hostile:
        result = verify(doc)
        assert result.status == "failed"
        assert result.reason
