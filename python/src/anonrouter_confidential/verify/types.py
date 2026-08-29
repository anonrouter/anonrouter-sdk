"""Normalized verdict + expectation types, mirroring the gateway's
``NormalizedAttestationResult`` and its snake_case JSON projection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

VerificationLevel = Literal[
    "hardware-verified",
    "sdk-verified",
    "provider-attested",
    "unverified",
    "unsupported",
]
PrivacyModality = Literal["tee", "e2ee"]


@dataclass(frozen=True)
class AttestationCheck:
    """A single fail-closed verification step. ``detail`` is always content-free."""

    name: str
    passed: bool
    required: bool
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "passed": self.passed,
            "required": self.required,
        }
        if self.detail is not None:
            out["detail"] = self.detail
        return out


@dataclass
class NormalizedVerdict:
    """OUR independent verification result. Dict keys are snake_case on the wire,
    per the SDK API contract. Contains only sanitized structured facts, never
    secrets, raw evidence bodies, prompts, or responses."""

    status: Literal["ok", "failed"]
    verification_level: VerificationLevel
    privacy_modality: PrivacyModality
    hardware_type: str
    measurement_identities: dict[str, str]
    model_weight_identity: str | None
    attested_tls_spki: str | None
    attested_encryption_key: str | None
    attested_signing_key: str | None
    nonce: str | None
    policy_source: str | None
    verifier_version: str
    supports_client_opaque_e2ee: bool
    reason: str | None
    checks: list[AttestationCheck]
    verified_at: str | None = None
    expires_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "verification_level": self.verification_level,
            "privacy_modality": self.privacy_modality,
            "hardware_type": self.hardware_type,
            "measurement_identities": dict(self.measurement_identities),
            "model_weight_identity": self.model_weight_identity,
            "attested_tls_spki": self.attested_tls_spki,
            "attested_encryption_key": self.attested_encryption_key,
            "attested_signing_key": self.attested_signing_key,
            "nonce": self.nonce,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "policy_source": self.policy_source,
            "verifier_version": self.verifier_version,
            "supports_client_opaque_e2ee": self.supports_client_opaque_e2ee,
            "reason": self.reason,
            "checks": [c.as_dict() for c in self.checks],
        }


@dataclass
class AttestationExpectations:
    """What the verifier binds evidence to. A mismatch on any of these is a
    fail-closed rejection."""

    provider: str
    upstream_model: str
    endpoint_identity: str
    nonce: str
    privacy_modality: PrivacyModality
    canonical_model: str | None = None
    route_id: str | None = None
    measurement_policy: dict[str, Any] | None = None
    # Injectable clock (ms) for deterministic freshness/expiry tests.
    now_ms: float | None = None
    max_evidence_age_ms: float | None = None
    cache_ttl_ms: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)
