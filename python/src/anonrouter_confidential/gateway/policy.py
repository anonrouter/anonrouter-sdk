"""The accepted-measurement policy for AnonRouter's own confidential gateway.

CRITICAL PROPERTY: a verifier must never download this policy from the server it is
verifying. A gateway that could hand a client the list of builds the client will
accept could always name itself. The policy therefore ships INSIDE this package
(``gateway_policies.json``, a parity-gated copy of the monorepo's canonical
``shared/gateway-policies.json``) or is supplied by the caller from an
independently distributed release manifest.

Nothing here reads the network. :func:`load_gateway_policy` parses an
already-obtained document and fails closed on anything unexpected.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Literal

from .binding import canonical_gateway_origin

_PACKAGE = "anonrouter_confidential"
_FILENAME = "gateway_policies.json"

_HEX = re.compile(r"^[0-9a-f]+$")


class GatewayPolicyError(ValueError):
    """A policy document that could not be parsed. Never a permissive default."""


@dataclass(frozen=True)
class GatewayPlatformMeasurements:
    """Platform-level measurements (firmware + OS image), when pinned."""

    #: Accepted MRTD values (48-byte SHA-384 hex).
    mr_td: list[str]
    #: Accepted MRCONFIGID values (48 bytes hex). Measured by the CPU at TD build
    #: time, so unlike anything in the event log the guest cannot re-narrate it.
    mr_config_id: list[str]
    #: Accepted RTMR0 (virtual firmware / VM configuration).
    rtmr0: list[str]
    #: Accepted RTMR1 (kernel).
    rtmr1: list[str]
    #: Accepted RTMR2 (kernel cmdline / initrd).
    rtmr2: list[str]
    #: Accepted dstack OS image hashes (32 bytes hex), as measured in the RTMR3
    #: ``os-image-hash`` event. One legible value instead of three opaque
    #: registers, and what ``dstack-mr`` reproduces.
    os_image_hash: list[str]


@dataclass(frozen=True)
class GatewayMeasurementPolicy:
    #: Where this policy came from, for the audit trail. Never a gateway URL.
    source: str
    #: Policy version so a stale pin is visible in output.
    version: str
    #: Origins this policy authorizes. A quote for another origin fails closed.
    origins: list[str]
    #: Accepted dstack application ids (lowercase hex, no 0x).
    app_ids: list[str]
    #: Accepted compose hashes: the exact reviewed configurations.
    compose_hashes: list[str]
    #: Accepted AnonRouter release identifiers.
    release_ids: list[str]
    #: Require the TD itself to terminate TLS and name the certificate the client
    #: is using. Fails closed when the platform gateway terminates TLS.
    require_in_tee_tls: bool
    #: Require the attested app-compose to declare public_logs=false, turning "we
    #: do not publish logs" from a promise into a measured configuration fact.
    require_private_logs: bool
    #: Require every image in the attested docker-compose to be digest-pinned.
    #: Without this the compose hash pins a tag that can be repointed later.
    require_digest_pinned_images: bool
    #: Require the quote's signature to chain to Intel's roots with TCB collateral.
    #:
    #: Without it, a client whose DCAP engine is missing, broken, or unbuilt
    #: silently accepts at the weaker level and reports success. This package ships
    #: NO DCAP engine, so a policy with this set true fails closed unless the caller
    #: supplies a ``chain_verifier``. That is deliberate.
    require_hardware_verified: bool
    #: Maximum age of the evidence document itself, in milliseconds.
    max_evidence_age_ms: float
    #: The KMS identity allowed to hold this app's derived keys, as it appears in
    #: the measured "key-provider" RTMR3 event. Omit only in local development:
    #: without it, a CVM whose keys came from a different key provider still passes
    #: every other check.
    key_provider_id: str | None = None
    #: Optional firmware/OS pinning. None accepts any platform stack.
    platform: GatewayPlatformMeasurements | None = None


def _hex_list(field: str, value: Any, exact_chars: int | None = None) -> list[str]:
    if not isinstance(value, list) or len(value) == 0:
        raise GatewayPolicyError(f"{field} must be a non-empty array")
    if len(value) > 64:
        raise GatewayPolicyError(f"{field} must contain at most 64 entries")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise GatewayPolicyError(f"{field} entries must be strings")
        normalized = entry.strip().lower().removeprefix("0x")
        if not _HEX.match(normalized):
            raise GatewayPolicyError(f"{field} entries must be hex")
        if exact_chars is not None and len(normalized) != exact_chars:
            raise GatewayPolicyError(f"{field} entries must be {exact_chars} hex characters")
        out.append(normalized)
    return out


def _string_list(field: str, value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) == 0:
        raise GatewayPolicyError(f"{field} must be a non-empty array")
    if len(value) > 64:
        raise GatewayPolicyError(f"{field} must contain at most 64 entries")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or len(entry.strip()) == 0:
            raise GatewayPolicyError(f"{field} entries must be non-empty strings")
        out.append(entry.strip())
    return out


def _required_bool(field: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise GatewayPolicyError(f"{field} must be a boolean")
    return value


def load_gateway_policy(raw: Any) -> GatewayMeasurementPolicy:
    """Parse an untrusted policy document.

    Every security-relevant switch is REQUIRED: there are no permissive defaults,
    so a truncated or hand-edited policy cannot silently disable a check.
    """
    if not isinstance(raw, dict):
        raise GatewayPolicyError("policy must be a JSON object")
    source = raw.get("source")
    if not isinstance(source, str) or len(source.strip()) == 0:
        raise GatewayPolicyError("policy.source is required")
    version = raw.get("version")
    if not isinstance(version, str) or len(version.strip()) == 0:
        raise GatewayPolicyError("policy.version is required")
    max_age = raw.get("maxEvidenceAgeMs")
    if (
        not isinstance(max_age, (int, float))
        or isinstance(max_age, bool)
        or max_age <= 0
        or max_age > 3_600_000
    ):
        raise GatewayPolicyError("policy.maxEvidenceAgeMs must be 1..3600000")

    platform: GatewayPlatformMeasurements | None = None
    raw_platform = raw.get("platform")
    if raw_platform is not None:
        if not isinstance(raw_platform, dict):
            raise GatewayPolicyError("policy.platform must be an object when present")
        platform = GatewayPlatformMeasurements(
            mr_td=_hex_list("policy.platform.mrTd", raw_platform.get("mrTd"), 96),
            mr_config_id=_hex_list("policy.platform.mrConfigId", raw_platform.get("mrConfigId"), 96),
            rtmr0=_hex_list("policy.platform.rtmr0", raw_platform.get("rtmr0"), 96),
            rtmr1=_hex_list("policy.platform.rtmr1", raw_platform.get("rtmr1"), 96),
            rtmr2=_hex_list("policy.platform.rtmr2", raw_platform.get("rtmr2"), 96),
            os_image_hash=_hex_list(
                "policy.platform.osImageHash", raw_platform.get("osImageHash"), 64
            ),
        )

    key_provider = raw.get("keyProviderId")
    return GatewayMeasurementPolicy(
        source=source.strip(),
        version=version.strip(),
        origins=[canonical_gateway_origin(o) for o in _string_list("policy.origins", raw.get("origins"))],
        app_ids=_hex_list("policy.appIds", raw.get("appIds")),
        compose_hashes=_hex_list("policy.composeHashes", raw.get("composeHashes"), 64),
        release_ids=_string_list("policy.releaseIds", raw.get("releaseIds")),
        key_provider_id=None
        if key_provider is None
        else _hex_list("policy.keyProviderId", [key_provider])[0],
        platform=platform,
        require_in_tee_tls=_required_bool("policy.requireInTeeTls", raw.get("requireInTeeTls")),
        require_private_logs=_required_bool("policy.requirePrivateLogs", raw.get("requirePrivateLogs")),
        require_digest_pinned_images=_required_bool(
            "policy.requireDigestPinnedImages", raw.get("requireDigestPinnedImages")
        ),
        require_hardware_verified=_required_bool(
            "policy.requireHardwareVerified", raw.get("requireHardwareVerified")
        ),
        max_evidence_age_ms=float(max_age),
    )


# ---- The shipped, origin-keyed registry --------------------------------------

#: ``published``  a released AnonRouter confidential plane, resolved by default.
#: ``candidate``  a reviewed but pre-release plane whose pins are expected to move.
#:                Requires an explicit opt-in, so a default call can never quietly
#:                pass against a plane the operator has not released.
GatewayPolicyStatus = Literal["published", "candidate"]


@dataclass(frozen=True)
class GatewayPolicyEntry:
    status: str
    #: When the pins in this entry were reviewed (ISO date).
    reviewed_at: str
    #: Free-form provenance note, carried into output for the audit trail.
    notes: str
    policy: GatewayMeasurementPolicy


@lru_cache(maxsize=1)
def _load_registry_document() -> dict[str, Any]:
    text = resources.files(_PACKAGE).joinpath(_FILENAME).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise GatewayPolicyError("gateway_policies.json did not decode to an object")
    return data


def _parse_entry(raw: Any) -> GatewayPolicyEntry:
    if not isinstance(raw, dict):
        raise GatewayPolicyError("registry entry must be an object")
    status = raw.get("status")
    if status not in ("published", "candidate"):
        raise GatewayPolicyError("registry entry status must be published or candidate")
    reviewed_at = raw.get("reviewedAt")
    notes = raw.get("notes")
    return GatewayPolicyEntry(
        status=status,
        reviewed_at=reviewed_at if isinstance(reviewed_at, str) else "",
        notes=notes if isinstance(notes, str) else "",
        policy=load_gateway_policy(raw.get("policy")),
    )


def gateway_policy_registry() -> list[GatewayPolicyEntry]:
    """Every pinned gateway policy this package ships, parsed and validated."""
    policies = _load_registry_document().get("policies")
    return [_parse_entry(entry) for entry in policies] if isinstance(policies, list) else []


def pinned_gateway_policy_for(
    origin: str, *, allow_candidate: bool = False
) -> GatewayPolicyEntry | None:
    """Resolve the shipped policy for an origin, or None when nothing is pinned.

    None is a fail-closed outcome, not a permissive one: the caller has no policy,
    so it cannot verify, so it must not proceed.
    """
    try:
        canonical = canonical_gateway_origin(origin)
    except ValueError:
        return None
    for entry in gateway_policy_registry():
        if canonical in entry.policy.origins and (entry.status == "published" or allow_candidate):
            return entry
    return None
