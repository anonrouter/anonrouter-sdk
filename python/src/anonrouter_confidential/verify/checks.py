"""Shared fail-closed check primitives + verdict assembly.

Kept tiny and pure so every provider verifier composes the SAME semantics: a
required check that fails forces overall status "failed", and the derived
verification level is never stronger than the checks justify.

These are the same check semantics AnonRouter's gateway applies server-side, so an
independent verdict and the gateway's own verdict agree by construction.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

from .types import (
    AttestationCheck,
    AttestationExpectations,
    NormalizedVerdict,
    VerificationLevel,
)

DEFAULT_EVIDENCE_MAX_AGE_MS = 5 * 60_000
DEFAULT_CACHE_TTL_MS = 5 * 60_000

_HEX_ONLY = re.compile(r"^[0-9a-f]+$")
_NONCE_SHAPE = re.compile(r"^[0-9a-f]{32,128}$", re.IGNORECASE)


def check(name: str, passed: bool, required: bool, detail: str | None = None) -> AttestationCheck:
    return AttestationCheck(name=name, passed=passed, required=required, detail=detail)


def _now_ms(expectations: AttestationExpectations) -> float:
    return expectations.now_ms if expectations.now_ms is not None else time.time() * 1000.0


class Envelope:
    """Defensively-read attestation envelope."""

    __slots__ = ("endpoint_identity", "fetched_at_ms", "payload")

    def __init__(self, fetched_at_ms: float, endpoint_identity: str, payload: Any) -> None:
        self.fetched_at_ms = fetched_at_ms
        self.endpoint_identity = endpoint_identity
        self.payload = payload


def read_envelope(evidence: Any, expectations: AttestationExpectations) -> Envelope:
    """A bare provider payload (no envelope) is tolerated: fetch time defaults to
    now and endpoint to the expectations."""
    if isinstance(evidence, dict) and "payload" in evidence:
        fetched = evidence.get("fetchedAtMs")
        endpoint = evidence.get("endpointIdentity")
        return Envelope(
            fetched_at_ms=float(fetched) if isinstance(fetched, (int, float)) else _now_ms(expectations),
            endpoint_identity=endpoint if isinstance(endpoint, str) else expectations.endpoint_identity,
            payload=evidence.get("payload"),
        )
    return Envelope(_now_ms(expectations), expectations.endpoint_identity, evidence)


def hex_equal(a: str | None, b: str | None) -> bool:
    """Lowercase-hex equality that does not short-circuit on length. Non-hex,
    empty, or mismatched-length inputs compare unequal."""
    if not a or not b:
        return False
    x = a.lower().removeprefix("0x")
    y = b.lower().removeprefix("0x")
    if len(x) != len(y) or len(x) == 0:
        return False
    if not _HEX_ONLY.match(x) or not _HEX_ONLY.match(y):
        return False
    diff = 0
    for cx, cy in zip(x, y):
        diff |= ord(cx) ^ ord(cy)
    return diff == 0


def all_required_passed(checks: list[AttestationCheck]) -> bool:
    return all((not c.required) or c.passed for c in checks)


def first_required_failure(checks: list[AttestationCheck]) -> str | None:
    for c in checks:
        if c.required and not c.passed:
            return c.name
    return None


def nonce_binding_check(expected_nonce: str, bound_nonce: str | None) -> AttestationCheck:
    if not _NONCE_SHAPE.match(expected_nonce or ""):
        return check("nonce_binding", False, True, "caller nonce missing or too short")
    return check(
        "nonce_binding",
        hex_equal(expected_nonce, bound_nonce),
        True,
        None if bound_nonce else "evidence bound no nonce",
    )


def freshness_check(evidence_epoch_ms: float | None, expectations: AttestationExpectations) -> AttestationCheck:
    now = _now_ms(expectations)
    max_age = expectations.max_evidence_age_ms if expectations.max_evidence_age_ms is not None else DEFAULT_EVIDENCE_MAX_AGE_MS
    if evidence_epoch_ms is None:
        return check("evidence_freshness", False, True, "evidence carried no verifiable timestamp")
    age = now - evidence_epoch_ms
    passed = -30_000 <= age <= max_age
    return check("evidence_freshness", passed, True, None if passed else "evidence outside freshness window")


def resolve_level(requested_level: VerificationLevel, checks: list[AttestationCheck]) -> VerificationLevel:
    if not all_required_passed(checks):
        return "unverified"
    return requested_level


def _iso(ms: float) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def assemble_result(
    *,
    expectations: AttestationExpectations,
    hardware_type: str,
    requested_level: VerificationLevel,
    measurement_identities: dict[str, str],
    model_weight_identity: str | None,
    attested_tls_spki: str | None,
    attested_encryption_key: str | None,
    attested_signing_key: str | None,
    bound_nonce: str | None,
    verifier_version: str,
    supports_client_opaque_e2ee: bool,
    checks: list[AttestationCheck],
) -> NormalizedVerdict:
    """Assemble the normalized verdict, deriving status/level/expiry from the
    checks. The requested level is CLAMPED: it is never emitted stronger than the
    checks justify, and callers never pass ``hardware-verified``."""
    now = _now_ms(expectations)
    ttl = expectations.cache_ttl_ms if expectations.cache_ttl_ms is not None else DEFAULT_CACHE_TTL_MS
    ok = all_required_passed(checks)
    level = resolve_level(requested_level, checks)
    policy = expectations.measurement_policy or {}
    return NormalizedVerdict(
        status="ok" if ok else "failed",
        verification_level=level,
        privacy_modality=expectations.privacy_modality,
        hardware_type=hardware_type,
        measurement_identities=measurement_identities,
        model_weight_identity=model_weight_identity,
        attested_tls_spki=attested_tls_spki,
        attested_encryption_key=attested_encryption_key,
        attested_signing_key=attested_signing_key,
        nonce=bound_nonce,
        policy_source=policy.get("source") if isinstance(policy, dict) else None,
        verifier_version=verifier_version,
        supports_client_opaque_e2ee=supports_client_opaque_e2ee,
        reason=None if ok else (first_required_failure(checks) or "verification_failed"),
        checks=checks,
        verified_at=_iso(now),
        expires_at=_iso(now + ttl),
    )


def failed_result(
    expectations: AttestationExpectations,
    reason: str,
    verifier_version: str,
    *,
    hardware_type: str = "unknown",
    supports_client_opaque_e2ee: bool = False,
) -> NormalizedVerdict:
    """A fully-failed verdict for the unsupported/error path. Never raises."""
    return assemble_result(
        expectations=expectations,
        hardware_type=hardware_type,
        requested_level="unverified",
        measurement_identities={},
        model_weight_identity=None,
        attested_tls_spki=None,
        attested_encryption_key=None,
        attested_signing_key=None,
        bound_nonce=None,
        verifier_version=verifier_version,
        supports_client_opaque_e2ee=supports_client_opaque_e2ee,
        checks=[check("evidence_present", False, True, reason)],
    )
