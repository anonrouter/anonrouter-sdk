"""Independent, fail-closed verification of AnonRouter GATEWAY attestation.

This is the client side of ``GET /v1/gateway/attestation``, the hop that answers
"is the AnonRouter data plane I am talking to the exact reviewed build running
inside an Intel TDX confidential VM?". The provider verifiers in
``anonrouter_confidential.verify`` answer the other hop. Neither implies the other.

It is deliberately pure: no network, no filesystem, no clock except an injected
``now_ms``, and no dependency on any vendor SDK.

The chain it establishes, in order:

1. The quote is a structurally valid, non-debug Intel TDX quote.
2. Its 64-byte report_data equals SHA-512 of the canonical binding object, so the
   TD asserted the caller's nonce, the app/instance identity, the compose
   measurement, the release id, the origin, the application key, and the transport
   claim, all at once, at quote time.
3. The plaintext event log replays to the quote's RTMR0..RTMR3.
4. The measured "compose-hash" event equals SHA-256 of the returned app-compose
   manifest, so the manifest is the one that ran.
5. The manifest's own contents satisfy the pinned policy.
6. The app id, compose hash, release id, and origin are on the pinned allowlist.
7. Optionally, the TD owns the TLS certificate the caller is using.

What this module does NOT do on its own is chain the quote's ECDSA signature to
Intel's roots. That requires DCAP collateral, which this package deliberately does
not ship, so it is injected through the pluggable ``TdxChainVerifier`` port.
Without one the honest verdict is ``provider-attested``, never
``hardware-verified``. This SDK does not upgrade a claim it did not check.

Mirrors ``@anonrouter/confidential``'s ``src/gateway/verify.ts`` check for check,
including every check name, so the two languages produce comparable verdicts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..tdx import TDX_TEE_TYPE, parse_tdx_quote
from ..verify.checks import check, hex_equal
from ..verify.types import AttestationCheck, VerificationLevel
from .app_compose import AttestedAppCompose, read_attested_app_compose
from .binding import (
    GatewayAttestationBinding,
    canonical_gateway_origin,
    gateway_binding_hash,
    normalize_gateway_binding,
)
from .event_log import (
    inconsistent_rtmr3_events,
    parse_event_log,
    replay_rtmrs,
    single_event_payload,
)
from .policy import GatewayMeasurementPolicy

#: A vm_config blob is bounded so a hostile response cannot pin the CPU parsing it.
_MAX_VM_CONFIG_CHARS = 65_536


class TdxChainVerifier(Protocol):
    """The pluggable port for chaining a TDX quote's ECDSA signature to Intel's roots.

    This package ships no engine (see ``gateway.dcap`` for why, and for the official
    adapter to the reviewed one). Supply an implementation to reach
    ``hardware-verified``; supply none and a policy demanding it fails closed.
    """

    implementation: str

    def verify_chain(self, quote: str, collateral: Any = None) -> Any:
        """Return ``(verified, tcb_status)`` or ``(verified, tcb_status, detail)``.

        The optional third element is a content-free explanation carried into the
        check's detail, so a refusal names itself: "engine binary not found" and
        "the signature is invalid" are very different problems.
        """
        ...


def _normalize_chain_outcome(outcome: Any) -> tuple[bool, str | None, str | None]:
    """Accept a 2- or 3-tuple from a chain verifier.

    The third element was added after the port shipped, so a 2-tuple from an older
    implementation stays valid. Anything else is a refusal rather than a crash:
    a malformed outcome must not read as a pass.
    """
    if isinstance(outcome, tuple) and len(outcome) >= 2:
        verified = outcome[0]
        status = outcome[1]
        detail = outcome[2] if len(outcome) >= 3 else None
        return (
            verified is True,
            status if isinstance(status, str) else None,
            detail if isinstance(detail, str) else None,
        )
    return False, None, "chain verifier returned a malformed outcome"


@dataclass
class GatewayVerificationResult:
    status: str
    verification_level: VerificationLevel
    checks: list[AttestationCheck]
    #: The first failed required check, or None. Sanitized and content-free.
    reason: str | None
    #: Normalized binding, present whenever it parsed.
    binding: GatewayAttestationBinding | None
    #: Parsed manifest facts, present whenever the manifest parsed.
    app_compose: AttestedAppCompose | None
    #: Measurements read out of the quote, for display and audit.
    measurements: dict[str, str] | None
    #: TCB status reported by the chain verifier, when one ran.
    tcb_status: str | None
    policy_source: str
    policy_version: str
    verified_at_ms: float
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "verification_level": self.verification_level,
            "reason": self.reason,
            "binding": self.binding.as_dict() if self.binding else None,
            "measurements": dict(self.measurements) if self.measurements else None,
            "tcb_status": self.tcb_status,
            "policy_source": self.policy_source,
            "policy_version": self.policy_version,
            "verified_at_ms": self.verified_at_ms,
            "checks": [c.as_dict() for c in self.checks],
        }


def _read_vm_config_os_image_hash(raw: Any) -> str | None:
    """Read ``os_image_hash`` out of the served vm_config blob.

    Returns None for anything unusable, so the caller records a visible gap rather
    than treating absence as agreement.
    """
    if not isinstance(raw, str) or len(raw) == 0 or len(raw) > _MAX_VM_CONFIG_CHARS:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    value = parsed.get("os_image_hash")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().removeprefix("0x")
    return normalized if len(normalized) == 64 and all(c in "0123456789abcdef" for c in normalized) else None


def _failed(
    checks: list[AttestationCheck],
    policy: GatewayMeasurementPolicy,
    now_ms: float,
    **partial: Any,
) -> GatewayVerificationResult:
    first = next((c for c in checks if c.required and not c.passed), None)
    result = GatewayVerificationResult(
        status="failed",
        verification_level="unverified",
        checks=checks,
        reason=first.name if first else "verification_failed",
        binding=None,
        app_compose=None,
        measurements=None,
        tcb_status=None,
        policy_source=policy.source,
        policy_version=policy.version,
        verified_at_ms=now_ms,
    )
    for key, value in partial.items():
        setattr(result, key, value)
    return result


def verify_gateway_attestation(
    evidence: Any,
    *,
    nonce: str,
    origin: str,
    policy: GatewayMeasurementPolicy,
    now_ms: float,
    observed_tls_spki_sha256: str | None = None,
    observed_tls_spki_supplied: bool = False,
    chain_verifier: TdxChainVerifier | None = None,
) -> GatewayVerificationResult:
    """Verify a gateway attestation document.

    Never raises on hostile input: every malformed field becomes a failed required
    check, so a caller that only reads ``status`` cannot be tricked by an exception
    path.

    ``observed_tls_spki_supplied`` distinguishes "not observed" (a browser cannot
    see its own certificate) from "observed and there is none". Python has no
    ``undefined``, so the two are separated explicitly rather than collapsed into
    None, which would silently turn an unmet gap into a mismatch or vice versa.
    """
    checks: list[AttestationCheck] = []
    doc = evidence if isinstance(evidence, dict) else {}

    # --- 1. Binding -----------------------------------------------------------
    try:
        binding = normalize_gateway_binding(doc.get("binding"))
        checks.append(check("binding_wellformed", True, True))
    except ValueError as exc:
        checks.append(check("binding_wellformed", False, True, str(exc)))
        return _failed(checks, policy, now_ms)

    # --- 2. Quote structure ---------------------------------------------------
    quote = parse_tdx_quote(doc.get("quote"))
    checks.append(check("quote_parsed", quote is not None, True))
    if quote is None:
        return _failed(checks, policy, now_ms, binding=binding)

    checks.append(
        check("quote_is_tdx", quote.tee_type == TDX_TEE_TYPE, True, f"tee_type=0x{quote.tee_type:x}")
    )
    # A debug TD lets the host inspect and modify guest memory. Nothing measured
    # inside it is confidential, so this is unconditionally fatal.
    checks.append(check("quote_not_debug", not quote.debug_enabled, True))

    measurements = {
        "mrTd": quote.mr_td,
        "mrConfigId": quote.mr_config_id,
        "rtmr0": quote.rtmr0,
        "rtmr1": quote.rtmr1,
        "rtmr2": quote.rtmr2,
        "rtmr3": quote.rtmr3,
    }

    # --- 3. report_data commits to the whole binding --------------------------
    try:
        binding_hash = gateway_binding_hash(binding)
    except ValueError as exc:
        checks.append(check("binding_hash_computed", False, True, str(exc)))
        return _failed(checks, policy, now_ms, binding=binding, measurements=measurements)
    checks.append(
        check("report_data_binds_binding", hex_equal(quote.report_data, binding_hash), True)
    )

    # --- 4. Freshness and origin, checked against what THIS client did --------
    try:
        expected_origin: str | None = canonical_gateway_origin(origin)
    except ValueError:
        expected_origin = None
    checks.append(check("nonce_matches_request", binding.nonce == nonce.lower(), True))
    checks.append(
        check(
            "origin_matches_connection",
            expected_origin is not None and binding.origin == expected_origin,
            True,
        )
    )

    # --- 5. Event log replays to the quote's registers ------------------------
    compose_hash_event: str | None = None
    instance_id_event: str | None = None
    app_id_event: str | None = None
    key_provider_event: str | None = None
    os_image_hash_event: str | None = None
    event_log_read = False
    try:
        events = parse_event_log(doc.get("event_log"))
        replayed = replay_rtmrs(events)
        replays = (
            hex_equal(replayed[0], quote.rtmr0)
            and hex_equal(replayed[1], quote.rtmr1)
            and hex_equal(replayed[2], quote.rtmr2)
            and hex_equal(replayed[3], quote.rtmr3)
        )
        checks.append(check("event_log_replays_rtmrs", replays, True))

        # Replay alone proves only that the DIGESTS are the measured ones. Each
        # RTMR3 digest must additionally commit to the human-readable name and
        # payload printed beside it, or a genuine quote could be re-served with a
        # rewritten compose-hash payload and still replay correctly.
        inconsistent = inconsistent_rtmr3_events(events)
        checks.append(
            check(
                "event_digests_commit_to_payloads",
                len(inconsistent) == 0,
                True,
                f"{len(inconsistent)} RTMR3 event(s) with a non-committing digest"
                if inconsistent
                else None,
            )
        )

        compose_hash_event = single_event_payload(events, "compose-hash")
        instance_id_event = single_event_payload(events, "instance-id")
        app_id_event = single_event_payload(events, "app-id")
        key_provider_event = single_event_payload(events, "key-provider")
        os_image_hash_event = single_event_payload(events, "os-image-hash")
        event_log_read = True
    except ValueError as exc:
        checks.append(check("event_log_replays_rtmrs", False, True, str(exc)))
        checks.append(check("event_digests_commit_to_payloads", False, True, str(exc)))

    # The compose hash the TD asserted in the binding must be the one hardware
    # measured. Without this the binding could name any configuration it liked.
    checks.append(
        check(
            "compose_hash_measured_in_rtmr3",
            compose_hash_event is not None and hex_equal(compose_hash_event, binding.compose_hash),
            True,
        )
    )
    # instance-id is measured too; when present it must agree with the binding.
    # "Absent" is only acceptable when the log was actually readable, otherwise an
    # unparsable log would silently satisfy this check.
    checks.append(
        check(
            "instance_id_measured",
            event_log_read
            and (instance_id_event is None or hex_equal(instance_id_event, binding.instance_id)),
            True,
            "no instance-id event in log" if instance_id_event is None else None,
        )
    )
    # app-id is measured independently of the binding, so a TD cannot claim an app
    # identity it was not provisioned with.
    checks.append(
        check(
            "app_id_measured",
            event_log_read and app_id_event is not None and hex_equal(app_id_event, binding.app_id),
            True,
        )
    )
    # key-provider names who may hold this app's derived keys. A CVM booted under a
    # different key provider is a different trust domain even at the same compose
    # hash, so this is pinned rather than merely reported.
    if policy.key_provider_id:
        expected = policy.key_provider_id.lower()
        # The payload is a JSON blob ({"name":"kms","id":"<k256 pubkey>"}) encoded
        # as hex, so match on the decoded text rather than the whole-field digest.
        decoded = ""
        if key_provider_event is not None:
            try:
                decoded = bytes.fromhex(key_provider_event).decode("utf-8", "replace").lower()
            except ValueError:
                decoded = ""
        checks.append(check("key_provider_pinned", expected in decoded, True))
    else:
        checks.append(
            check(
                "key_provider_pinned",
                False,
                False,
                "policy pins no key provider; a CVM under a different KMS would still pass",
            )
        )

    # vm_config is what lets someone recompute MRTD and RTMR0..2 offline with
    # dstack-mr. It is served by the CVM, so on its own it is a claim; it becomes
    # evidence only once it agrees with something hardware measured. The measured
    # `os-image-hash` event is that anchor.
    vm_config_os_image = _read_vm_config_os_image_hash(doc.get("vm_config"))
    if os_image_hash_event is not None and vm_config_os_image is not None:
        checks.append(
            check(
                "vm_config_matches_measured_os_image",
                hex_equal(os_image_hash_event, vm_config_os_image),
                True,
            )
        )
    else:
        checks.append(
            check(
                "vm_config_matches_measured_os_image",
                False,
                False,
                "no os-image-hash event in the log to anchor vm_config against"
                if os_image_hash_event is None
                else "evidence carries no vm_config.os_image_hash, so offline measurement "
                "recomputation is unanchored",
            )
        )

    # --- 6. The manifest is the measured one, and says what it should ---------
    app_compose: AttestedAppCompose | None = None
    try:
        app_compose = read_attested_app_compose(doc.get("app_compose"))
        checks.append(check("app_compose_parsed", True, True))
    except ValueError as exc:
        checks.append(check("app_compose_parsed", False, True, str(exc)))
    checks.append(
        check(
            "app_compose_matches_measurement",
            app_compose is not None and hex_equal(app_compose.compose_hash, binding.compose_hash),
            True,
        )
    )

    if policy.require_private_logs:
        checks.append(
            check(
                "compose_public_logs_disabled",
                app_compose is not None and app_compose.public_logs is False,
                True,
                f"public_logs={app_compose.public_logs}" if app_compose else None,
            )
        )
    if policy.require_digest_pinned_images:
        unpinned = [i for i in app_compose.images if not i.digest_pinned] if app_compose else []
        checks.append(
            check(
                "compose_images_digest_pinned",
                app_compose is not None and len(app_compose.images) > 0 and len(unpinned) == 0,
                True,
                f"{len(unpinned)} image reference(s) not digest-pinned" if unpinned else None,
            )
        )

    # --- 7. Locally pinned identity -------------------------------------------
    checks.append(
        check("app_id_pinned", any(hex_equal(i, binding.app_id) for i in policy.app_ids), True)
    )
    checks.append(
        check(
            "compose_hash_pinned",
            any(hex_equal(h, binding.compose_hash) for h in policy.compose_hashes),
            True,
        )
    )
    checks.append(check("release_pinned", binding.release_id in policy.release_ids, True))
    checks.append(check("origin_pinned", binding.origin in policy.origins, True))

    if policy.platform:
        p = policy.platform
        checks.append(
            check(
                "platform_measurements_pinned",
                any(hex_equal(v, quote.mr_td) for v in p.mr_td)
                and any(hex_equal(v, quote.mr_config_id) for v in p.mr_config_id)
                and any(hex_equal(v, quote.rtmr0) for v in p.rtmr0)
                and any(hex_equal(v, quote.rtmr1) for v in p.rtmr1)
                and any(hex_equal(v, quote.rtmr2) for v in p.rtmr2),
                True,
            )
        )
        # Pinned separately from the registers above because it is the one platform
        # value an operator can read off a release note and compare by eye.
        checks.append(
            check(
                "os_image_pinned",
                os_image_hash_event is not None
                and any(hex_equal(v, os_image_hash_event) for v in p.os_image_hash),
                True,
                "no os-image-hash event in the log" if os_image_hash_event is None else None,
            )
        )

    # --- 8. Transport binding --------------------------------------------------
    if policy.require_in_tee_tls:
        checks.append(check("transport_terminates_in_tee", binding.transport == "in-tee-tls", True))
        if observed_tls_spki_supplied:
            checks.append(
                check(
                    "tls_certificate_bound_to_quote",
                    hex_equal(observed_tls_spki_sha256, binding.tls_spki_sha256),
                    True,
                )
            )
        else:
            # Advisory: the caller could not observe its own certificate (a browser
            # cannot). Recorded so the gap is visible rather than assumed away.
            checks.append(
                check(
                    "tls_certificate_bound_to_quote",
                    False,
                    False,
                    "caller did not observe its TLS certificate",
                )
            )
    else:
        checks.append(
            check(
                "transport_terminates_in_tee",
                binding.transport == "in-tee-tls",
                False,
                "TLS terminates at the platform gateway, not inside the TD"
                if binding.transport == "gateway-tls"
                else None,
            )
        )

    # --- 9. Evidence expiry ----------------------------------------------------
    # The nonce is the primary anti-replay proof, so this is defence in depth. Note
    # WHY the "no timestamp" case fails rather than passing: a document that cannot
    # be aged has not been shown to be fresh, and treating unmeasurable as
    # acceptable is how an expiry check quietly stops existing.
    issued_at = doc.get("issued_at_ms")
    age = (
        now_ms - issued_at
        if isinstance(issued_at, (int, float)) and not isinstance(issued_at, bool)
        else None
    )
    checks.append(
        check(
            "evidence_recent",
            age is not None and -60_000 <= age <= policy.max_evidence_age_ms,
            policy.require_evidence_expiry,
            "no issued_at_ms" if age is None else f"age_ms={age}",
        )
    )

    # --- 10. Hardware chain (pluggable) ---------------------------------------
    tcb_status: str | None = None
    chain_verified = False
    if chain_verifier is not None:
        engine_verified, tcb_status, chain_detail = _normalize_chain_outcome(
            chain_verifier.verify_chain(str(doc.get("quote")), None)
        )
        # The TCB status is enforced against the policy EVEN WHEN the verifier said
        # verified. A quote can chain perfectly to Intel's roots while the platform
        # holding your data has known unpatched vulnerabilities, and an engine's own
        # idea of an acceptable status is not this policy's decision to delegate.
        tcb_acceptable = tcb_status is not None and any(
            s.lower() == tcb_status.lower() for s in policy.acceptable_tcb_statuses
        )
        chain_verified = bool(engine_verified) and tcb_acceptable
        checks.append(
            check(
                "quote_signature_chain",
                bool(engine_verified),
                True,
                # The engine's own reason first: "engine binary not found" and "the
                # signature is invalid" are very different problems and a bare
                # "no TCB status" would hide which one a reader is looking at.
                chain_detail
                or (f"tcb={tcb_status}" if tcb_status else "chain verifier reported no TCB status"),
            )
        )
        checks.append(
            check(
                "tcb_status_acceptable",
                tcb_acceptable,
                True,
                "chain verifier returned no TCB status, so it cannot be checked against the policy"
                if tcb_status is None
                else f"tcb={tcb_status}, accepted={'|'.join(policy.acceptable_tcb_statuses)}",
            )
        )
    else:
        # Required when the policy demands hardware verification, so a client whose
        # DCAP engine is missing or unbuilt fails loudly instead of quietly
        # accepting at the weaker level and reporting success.
        checks.append(
            check(
                "quote_signature_chain",
                False,
                policy.require_hardware_verified,
                "policy requires hardware verification but no DCAP chain verifier was supplied"
                if policy.require_hardware_verified
                else "no DCAP chain verifier supplied; verdict capped at provider-attested",
            )
        )
        # Recorded even with no verifier, so the check set is the same shape either
        # way and a reader diffing two verdicts is not left wondering whether the
        # TCB was checked and passed or never looked at.
        checks.append(
            check(
                "tcb_status_acceptable",
                False,
                policy.require_hardware_verified,
                "no chain verifier supplied, so no TCB status was reported to check",
            )
        )

    if any(c.required and not c.passed for c in checks):
        return _failed(
            checks,
            policy,
            now_ms,
            binding=binding,
            app_compose=app_compose,
            measurements=measurements,
            tcb_status=tcb_status,
        )

    return GatewayVerificationResult(
        status="ok",
        verification_level="hardware-verified" if chain_verified else "provider-attested",
        checks=checks,
        reason=None,
        binding=binding,
        app_compose=app_compose,
        measurements=measurements,
        tcb_status=tcb_status,
        policy_source=policy.source,
        policy_version=policy.version,
        verified_at_ms=now_ms,
    )
