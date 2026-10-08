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
from typing import Any, Literal, cast

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


#: Which kind of confidential platform a policy describes. Each kind has its own
#: security floor and evidence rules. A document WITHOUT ``platformKind`` is the
#: legacy phala-dstack-kms form and parses exactly as it always has.
#: ``gcp-tdx-native`` is a Google Cloud Intel TDX content node with guest-only,
#: per-boot keys (ephemeral key provider, no KMS) pinned through the hardware
#: registers in the quote; never vTPM evidence.
GatewayPlatformKind = Literal["phala-dstack-kms", "gcp-tdx-native"]

GATEWAY_PLATFORM_KINDS: tuple[str, ...] = ("phala-dstack-kms", "gcp-tdx-native")

#: Whether a platform kind's boot chain has been qualified for this SDK release.
#: gcp-tdx-native is NOT: a small C4 TDX VM produced a genuine natively verified
#: quote, but no AnonRouter guest has yet proved that Google's firmware measures
#: its UKI, command line and verity root into RTMR1/RTMR2, nor that RTMR3 covers
#: the code that runs. Until a reviewed SDK release flips this, the packaged
#: registry and the signed feed refuse the kind and the verifier fails it unless
#: the caller explicitly opted into an unqualified pilot.
GATEWAY_PLATFORM_QUALIFIED: dict[str, bool] = {
    "phala-dstack-kms": True,
    "gcp-tdx-native": False,
}

#: The longest validity window a single tuple may claim (366 days).
MAX_RELEASE_TUPLE_LIFETIME_MS = 31_622_400_000
#: At most this many tuples, so a hostile policy cannot pin the CPU.
MAX_RELEASE_TUPLES = 64
_MAX_SAFE_INTEGER = 2**53 - 1


@dataclass(frozen=True)
class GatewayReleaseTuple:
    """One approved release, as the WHOLE tuple of values observed together.

    A policy listing several tuples accepts evidence matching ANY ONE of them
    completely, never a mixture. Firmware rolls and machine shapes are additional
    complete tuples. Field names mirror the JSON document.
    """

    tuple_id: str
    release_id: str
    app_id: str
    compose_hash: str
    mr_td: str
    mr_config_id: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    #: Exact payload (lowercase hex) of the measured RTMR3 key-provider event.
    key_provider_payload: str
    not_before_ms: int
    expires_at_ms: int
    #: phala-dstack-kms only: the measured dstack os-image-hash event.
    os_image_hash: str | None = None


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
    #: TCB statuses this policy accepts from a chain verifier.
    #:
    #: A DCAP verdict is not a boolean: a quote can verify against Intel's roots
    #: while the platform's TCB is out of date, meaning known vulnerabilities are
    #: unpatched on the machine holding your data. Accepting ``OutOfDate`` because
    #: the signature checked out is the mistake this list exists to prevent.
    #: Enforced even when the verifier reports ``verified: True``.
    acceptable_tcb_statuses: list[str]
    #: Require the evidence document to carry a timestamp inside the age window.
    #:
    #: The nonce is the real anti-replay proof, so this is defence in depth. It
    #: matters because a document with NO timestamp cannot be aged at all, and
    #: treating "unmeasurable" as "fresh enough" is the quiet way an expiry check
    #: stops existing.
    require_evidence_expiry: bool
    #: Maximum age of the evidence document itself, in milliseconds.
    max_evidence_age_ms: float
    #: The KMS identity allowed to hold this app's derived keys, as it appears in
    #: the measured "key-provider" RTMR3 event. Omit only in local development:
    #: without it, a CVM whose keys came from a different key provider still passes
    #: every other check.
    key_provider_id: str | None = None
    #: Optional firmware/OS pinning. None accepts any platform stack.
    platform: GatewayPlatformMeasurements | None = None
    #: Explicit platform discriminator. None is the legacy phala-dstack-kms form.
    #: Present means the tuple form: ``release_tuples`` is the only source of
    #: accepted identities and the list fields above are derived for display.
    platform_kind: str | None = None
    #: Tuple form only: the approved releases, evaluated as OR of whole tuples.
    release_tuples: list[GatewayReleaseTuple] | None = None


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


_RELEASE_LABEL = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")
_LEGACY_IDENTITY_FIELDS = ("appIds", "composeHashes", "releaseIds", "keyProviderId", "platform")
_TUPLE_POLICY_FIELDS = frozenset({
    "platformKind", "source", "version", "origins", "releaseTuples", "requireInTeeTls",
    "requirePrivateLogs", "requireDigestPinnedImages", "requireHardwareVerified",
    "acceptableTcbStatuses", "requireEvidenceExpiry", "maxEvidenceAgeMs",
})
_TUPLE_FIELDS = (
    "tupleId", "releaseId", "appId", "composeHash", "mrTd", "mrConfigId", "rtmr0", "rtmr1",
    "rtmr2", "keyProviderPayload", "notBeforeMs", "expiresAtMs",
)
_KEY_PROVIDER_NAME = {"phala-dstack-kms": "kms", "gcp-tdx-native": "none"}
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")


def gateway_policy_platform_kind(policy: GatewayMeasurementPolicy) -> str:
    """The platform a parsed policy describes; the legacy form is phala-dstack-kms."""
    return policy.platform_kind or "phala-dstack-kms"


def gateway_policy_requires_retained_connection(policy: GatewayMeasurementPolicy) -> bool:
    """True when the TLS key must be observed on the socket that carries content.

    Behind a load balancer with a different key per node, a separately observed
    certificate proves nothing about the node that receives the request.
    """
    return gateway_policy_platform_kind(policy) == "gcp-tdx-native"


def _exact_hex(field: str, value: Any, chars: int) -> str:
    if not isinstance(value, str) or len(value) != chars or not _LOWER_HEX.match(value):
        raise GatewayPolicyError(f"{field} must be exactly {chars} lowercase hex characters")
    return value


def _tuple_time(field: str, value: Any) -> int:
    # JSON has one number type: 1000 and 1000.0 are the same value to the JS
    # verifier, so an integral float is accepted here too and a fraction is not.
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        raise GatewayPolicyError(f"{field} must be a non-negative safe integer (epoch ms)")
    return value


def _tuple_document(value: Any) -> Any:
    """Accept a parsed tuple as well, so the floor can re-validate it."""
    if isinstance(value, GatewayReleaseTuple):
        doc: dict[str, Any] = {
            "tupleId": value.tuple_id, "releaseId": value.release_id, "appId": value.app_id,
            "composeHash": value.compose_hash, "mrTd": value.mr_td,
            "mrConfigId": value.mr_config_id, "rtmr0": value.rtmr0, "rtmr1": value.rtmr1,
            "rtmr2": value.rtmr2, "keyProviderPayload": value.key_provider_payload,
            "notBeforeMs": value.not_before_ms, "expiresAtMs": value.expires_at_ms,
        }
        if value.os_image_hash is not None:
            doc["osImageHash"] = value.os_image_hash
        return doc
    return value


def validate_gateway_release_tuple(kind: str, raw: Any, index: int) -> GatewayReleaseTuple:
    """Validate one tuple for its platform kind. Values must already be canonical
    lowercase hex: a tuple is compared exactly, so it is written exactly."""
    at = f"policy.releaseTuples[{index}]"
    raw = _tuple_document(raw)
    if not isinstance(raw, dict):
        raise GatewayPolicyError(f"{at} must be an object")
    expected = [*_TUPLE_FIELDS, "osImageHash"] if kind == "phala-dstack-kms" else list(_TUPLE_FIELDS)
    keys = list(raw)
    if len(keys) != len(expected) or any(key not in expected for key in keys):
        # gcp-tdx-native has no osImageHash (its OS is RTMR1/RTMR2) and no
        # vTPM/PCR field of any kind: an unknown field is refused, never ignored.
        raise GatewayPolicyError(f"{at} must have exactly the fields {', '.join(expected)}")
    for name in ("tupleId", "releaseId"):
        if not isinstance(raw[name], str) or not _RELEASE_LABEL.match(raw[name]):
            raise GatewayPolicyError(f"{at}.{name} must be 1..128 chars of [A-Za-z0-9._:@+-]")
    app_id = raw["appId"]
    if not isinstance(app_id, str) or not re.fullmatch(r"[0-9a-f]{1,512}", app_id):
        raise GatewayPolicyError(f"{at}.appId must be lowercase hex")
    payload = raw["keyProviderPayload"]
    if (
        not isinstance(payload, str)
        or not 2 <= len(payload) <= 2048
        or len(payload) % 2 != 0
        or not _LOWER_HEX.match(payload)
    ):
        raise GatewayPolicyError(f"{at}.keyProviderPayload must be 2..2048 lowercase hex characters")
    try:
        provider = json.loads(bytes.fromhex(payload).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise GatewayPolicyError(f"{at}.keyProviderPayload must decode to a UTF-8 JSON object") from exc
    if not isinstance(provider, dict) or provider.get("name") != _KEY_PROVIDER_NAME[kind]:
        raise GatewayPolicyError(
            f"{at}.keyProviderPayload must name the {_KEY_PROVIDER_NAME[kind]} key provider for {kind}"
        )
    not_before = _tuple_time(f"{at}.notBeforeMs", raw["notBeforeMs"])
    expires_at = _tuple_time(f"{at}.expiresAtMs", raw["expiresAtMs"])
    if expires_at <= not_before or expires_at - not_before > MAX_RELEASE_TUPLE_LIFETIME_MS:
        raise GatewayPolicyError(
            f"{at} validity must be a non-empty window of at most {MAX_RELEASE_TUPLE_LIFETIME_MS} ms"
        )
    return GatewayReleaseTuple(
        tuple_id=raw["tupleId"],
        release_id=raw["releaseId"],
        app_id=app_id,
        compose_hash=_exact_hex(f"{at}.composeHash", raw["composeHash"], 64),
        mr_td=_exact_hex(f"{at}.mrTd", raw["mrTd"], 96),
        mr_config_id=_exact_hex(f"{at}.mrConfigId", raw["mrConfigId"], 96),
        rtmr0=_exact_hex(f"{at}.rtmr0", raw["rtmr0"], 96),
        rtmr1=_exact_hex(f"{at}.rtmr1", raw["rtmr1"], 96),
        rtmr2=_exact_hex(f"{at}.rtmr2", raw["rtmr2"], 96),
        key_provider_payload=payload,
        not_before_ms=not_before,
        expires_at_ms=expires_at,
        os_image_hash=_exact_hex(f"{at}.osImageHash", raw["osImageHash"], 64)
        if kind == "phala-dstack-kms"
        else None,
    )


def _validate_release_tuples(kind: str, value: Any) -> list[GatewayReleaseTuple]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RELEASE_TUPLES:
        raise GatewayPolicyError(f"policy.releaseTuples must contain 1..{MAX_RELEASE_TUPLES} tuples")
    tuples = [validate_gateway_release_tuple(kind, entry, i) for i, entry in enumerate(value)]
    if len({t.tuple_id for t in tuples}) != len(tuples):
        raise GatewayPolicyError("policy.releaseTuples tupleIds must be unique")
    return tuples


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def assert_gateway_platform_security_floor(policy: GatewayMeasurementPolicy) -> None:
    """The per-kind floor every policy must meet before evidence is judged.

    The legacy form keeps exactly its historical floor. The tuple form also
    refuses a mixed document and re-validates every tuple.
    """
    def refuse(why: str) -> None:
        raise GatewayPolicyError(f"policy security floor: {why}")

    if (
        not policy.require_hardware_verified
        or not policy.require_in_tee_tls
        or not policy.require_private_logs
        or not policy.require_digest_pinned_images
        or not policy.require_evidence_expiry
        or policy.max_evidence_age_ms > 300_000
        or policy.acceptable_tcb_statuses != ["UpToDate"]
    ):
        refuse("policy weakens mandatory security requirements")
    if policy.platform_kind is None:
        if policy.release_tuples is not None:
            refuse("release tuples require an explicit platformKind")
        if not policy.key_provider_id or not policy.platform:
            refuse("policy weakens mandatory security requirements")
        return
    if policy.platform_kind not in GATEWAY_PLATFORM_KINDS:
        refuse("unknown platformKind")
    if policy.key_provider_id is not None or policy.platform is not None:
        refuse("a tuple-form policy cannot also carry independent platform or key-provider allowlists")
    try:
        tuples = _validate_release_tuples(policy.platform_kind, policy.release_tuples)
    except GatewayPolicyError as exc:
        refuse(str(exc))
        return
    if (
        policy.app_ids != _unique([t.app_id for t in tuples])
        or policy.compose_hashes != _unique([t.compose_hash for t in tuples])
        or policy.release_ids != _unique([t.release_id for t in tuples])
    ):
        refuse("derived identity lists disagree with the release tuples")


def _load_tuple_gateway_policy(raw: dict[str, Any]) -> GatewayMeasurementPolicy:
    kind = raw.get("platformKind")
    if not isinstance(kind, str) or kind not in GATEWAY_PLATFORM_KINDS:
        raise GatewayPolicyError(
            f"policy.platformKind must be one of {', '.join(GATEWAY_PLATFORM_KINDS)}"
        )
    for name in _LEGACY_IDENTITY_FIELDS:
        if name in raw:
            # Ambiguity is refused rather than resolved: a document carrying both
            # forms could be read as either, and they accept different evidence.
            raise GatewayPolicyError(f"policy.{name} is not allowed with platformKind; use releaseTuples")
    unknown = [key for key in raw if key not in _TUPLE_POLICY_FIELDS]
    if unknown:
        raise GatewayPolicyError(f"policy has unknown field(s): {', '.join(unknown)}")
    tuples = _validate_release_tuples(kind, raw.get("releaseTuples"))
    base = _load_legacy_gateway_policy({
        **raw,
        "appIds": _unique([t.app_id for t in tuples]),
        "composeHashes": _unique([t.compose_hash for t in tuples]),
        "releaseIds": _unique([t.release_id for t in tuples]),
    })
    return GatewayMeasurementPolicy(
        **{**base.__dict__, "platform_kind": cast(str, kind), "release_tuples": tuples}
    )


def load_gateway_policy(raw: Any) -> GatewayMeasurementPolicy:
    """Parse an untrusted policy document.

    Every security-relevant switch is REQUIRED: there are no permissive defaults,
    so a truncated or hand-edited policy cannot silently disable a check.

    Two forms exist. Without ``platformKind`` the document is the legacy
    phala-dstack-kms form and parses exactly as it always has. With
    ``platformKind`` it must carry ``releaseTuples`` and none of the independent
    allowlists; mixing the two forms is refused.
    """
    if not isinstance(raw, dict):
        raise GatewayPolicyError("policy must be a JSON object")
    if "platformKind" in raw:
        return _load_tuple_gateway_policy(raw)
    if "releaseTuples" in raw:
        raise GatewayPolicyError("policy.releaseTuples requires an explicit platformKind")
    return _load_legacy_gateway_policy(raw)


def _load_legacy_gateway_policy(raw: dict[str, Any]) -> GatewayMeasurementPolicy:
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
        acceptable_tcb_statuses=_string_list(
            "policy.acceptableTcbStatuses", raw.get("acceptableTcbStatuses")
        ),
        require_evidence_expiry=_required_bool(
            "policy.requireEvidenceExpiry", raw.get("requireEvidenceExpiry")
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
    policy = load_gateway_policy(raw.get("policy"))
    # The package must never ship an approval for a platform whose boot chain this
    # release has not qualified, not even as a candidate.
    if not GATEWAY_PLATFORM_QUALIFIED.get(gateway_policy_platform_kind(policy), False):
        raise GatewayPolicyError("registry entry names a platform kind this release has not qualified")
    return GatewayPolicyEntry(
        status=status,
        reviewed_at=reviewed_at if isinstance(reviewed_at, str) else "",
        notes=notes if isinstance(notes, str) else "",
        policy=policy,
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
