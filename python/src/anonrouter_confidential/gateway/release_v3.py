"""Owner-signed release policy v3: the GCP-native gateway approval path.

The owner (two Ed25519 custodian keys, usb then laptop) signs a release policy
once per release or revocation. It has NO expiry: it stays valid until a higher
sequence supersedes it. This module verifies such a policy against an owner root
the caller pins (by default the production root packaged with this SDK), keeps a
monotonic checkpoint (no lower sequence, no fork at one sequence, no revocation
reversal) and turns it into a gcp-tdx-native gateway policy whose exact register
tuples the verifier matches against the connection-bound quote.

Transport is untrusted. Keys never come from the feed. When the feed is
unreachable the last verified policy serves for at most one hour, then every
resolve refuses until the feed answers again. Mirrors the JavaScript
``release-v3.ts`` byte for byte; shared vectors in
``shared/vectors/release-policy-v3.json``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable
from functools import lru_cache
from importlib import resources
from typing import Any

import httpx
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .binding import canonical_gateway_origin
from .policy import (
    MAX_RELEASE_V3_REVOKED_TUPLES,
    MAX_RELEASE_V3_TUPLES,
    GatewayMeasurementPolicy,
    GatewayPolicyError,
    assert_gateway_platform_security_floor,
    validate_gateway_measured_tuple_v3,
)
from .release_v3_canonical import (
    RELEASE_V3_DIGEST_PROTOCOL,
    ReleaseCanonicalError,
    canonical_release_bytes,
    release_digest_hex,
    release_policy_sha256,
    release_tuple_digest,
)
from .state import FileGatewayPolicyStateStore

RELEASE_V3_ENVELOPE_PROTOCOL = "anonrouter-content-release-envelope-v3"
RELEASE_V3_SIGNATURE_DOMAIN_PREFIX = "anonrouter-content-release-v3/authority/"
RELEASE_V3_POLICY_KIND = "content-node-release-policy"
RELEASE_V3_ROLES = ("release-policy", "generation")
#: Fixed signer order: both required, usb first.
RELEASE_V3_KEY_IDS = ("custodian.prod.usb", "custodian.prod.laptop")
#: Longest a cached policy may serve while the feed is unreachable.
MAX_RELEASE_V3_OFFLINE_MS = 3_600_000
MAX_RELEASE_V3_REFRESH_MS = 300_000
MAX_RELEASE_POLICY_V3_BYTES = 1_048_576
#: Intel TCB statuses an owner-signed grace may list (never UpToDate, never Revoked).
RELEASE_V3_GRACE_TCB_STATUSES = (
    "ConfigurationAndSWHardeningNeeded", "ConfigurationNeeded", "OutOfDate", "OutOfDateConfigurationNeeded",
    "SWHardeningNeeded",
)
MAX_RELEASE_V3_TCB_GRACE_MS = 90 * 24 * 60 * 60 * 1000
MAX_RELEASE_V3_TCB_GRACE_ADVISORIES = 64

_PAYLOAD_FIELDS = ("protocol", "kind", "deploymentId", "sequence", "issuedAtMs", "tuples", "revokedTuples",
                   "revokedGenerations", "minimumGenerationRevision", "maxEvidenceAgeMs", "tcbStatus")
#: Optional signed payload fields. Absent leaves the canonical payload and digest unchanged.
_OPTIONAL_PAYLOAD_FIELDS = ("tcbGrace", "requireGcePzid")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}\Z")
_HEX32 = re.compile(r"^[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"^[0-9a-f]{128}\Z")
_ADVISORY_ID = re.compile(r"^INTEL-[A-Z]{2,8}-[0-9]{4,8}\Z")
_MAX_SAFE_INTEGER = 2**53 - 1


class ReleasePolicyV3Error(GatewayPolicyError):
    """Every v3 refusal. Fail-closed: callers never fall back to another policy.

    ``code`` matches the JavaScript ``ReleasePolicyV3Error.code``.
    """

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(f"release policy v3: {code}" + (f" ({detail})" if detail else ""))
        self.code = code


def _refuse(code: str, detail: str | None = None) -> Any:
    raise ReleasePolicyV3Error(code, detail)


def _record(value: Any, code: str = "contract_invalid") -> dict[str, Any]:
    if not isinstance(value, dict):
        _refuse(code, "expected object")
    return value


def _fields(value: dict[str, Any], names: tuple[str, ...] | list[str], code: str = "contract_invalid") -> None:
    if len(value) != len(names) or any(key not in names for key in value):
        _refuse(code, "unexpected or missing fields")


def _safe_integer(value: Any, minimum: int, maximum: int = _MAX_SAFE_INTEGER, code: str = "contract_invalid") -> int:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if type(value) is not int or not minimum <= value <= maximum:
        _refuse(code, "invalid integer")
    return int(value)


def _identifier(value: Any, code: str = "contract_invalid") -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        _refuse(code, "invalid identifier")
    return value


def _hex32_list(value: Any, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        _refuse("contract_invalid", "invalid digest list")
    for entry in value:
        if not isinstance(entry, str) or not _HEX32.match(entry):
            _refuse("contract_invalid", "invalid digest")
    return list(value)


def _ascending(values: list[str]) -> bool:
    return all(values[i - 1] < values[i] for i in range(1, len(values)))


# --------------------------------------------------------------------------- trust


@lru_cache(maxsize=1)
def _packaged_authority_text() -> str:
    return (resources.files("anonrouter_confidential") / "release_policy_v3_authority.json").read_text("utf-8")


def packaged_release_policy_v3_authority() -> dict[str, Any]:
    """Independently packaged production owner root and feed location. No image pins."""
    return dict(json.loads(_packaged_authority_text()))


def release_owner_root_sha256(trust: dict[str, Any]) -> str:
    """ownerRootSha256 = digest("release-owner-root", {deploymentId, groupId, keys})."""
    try:
        return release_digest_hex("release-owner-root", {
            "deploymentId": trust["deploymentId"], "groupId": trust["groupId"],
            "keys": [{"keyId": k["keyId"], "publicKey": k["publicKey"]} for k in trust["keys"]],
        })
    except (ReleaseCanonicalError, KeyError, TypeError):
        return _refuse("trust_invalid", "owner root fields are not canonical")


def validate_release_policy_v3_trust(trust: Any) -> None:
    t = _record(trust, "trust_invalid")
    _fields(t, ("deploymentId", "groupId", "keys", "ownerRootSha256", "minimumPolicySequence"), "trust_invalid")
    _identifier(t["deploymentId"], "trust_invalid")
    _identifier(t["groupId"], "trust_invalid")
    _safe_integer(t["minimumPolicySequence"], 1, code="trust_invalid")
    keys = t["keys"]
    if not isinstance(keys, list) or len(keys) != len(RELEASE_V3_KEY_IDS):
        _refuse("trust_invalid", "expected the usb and laptop keys")
    for index, entry in enumerate(keys):
        key = _record(entry, "trust_invalid")
        _fields(key, ("keyId", "publicKey"), "trust_invalid")
        if key["keyId"] != RELEASE_V3_KEY_IDS[index] or not isinstance(key["publicKey"], str) \
                or not _HEX32.match(key["publicKey"]):
            _refuse("trust_invalid", "keys must be usb then laptop, 32-byte lowercase hex")
    if keys[0]["publicKey"] == keys[1]["publicKey"]:
        _refuse("trust_invalid", "owner keys must be distinct")
    if not isinstance(t["ownerRootSha256"], str) or not _HEX32.match(t["ownerRootSha256"]) \
            or release_owner_root_sha256(t) != t["ownerRootSha256"]:
        _refuse("wrong_owner_root", "pinned owner root does not match its keys")


# ------------------------------------------------------------------------ envelope


def release_envelope_v3_message(role: str, group_id: str, owner_root_sha256: str, payload: Any) -> bytes:
    """msg = SHA256(ASCII(prefix + role + "\\0") || canonical({groupId, ownerRootSha256, payload}))."""
    try:
        body = canonical_release_bytes({"groupId": group_id, "ownerRootSha256": owner_root_sha256, "payload": payload})
    except ReleaseCanonicalError:
        return _refuse("contract_invalid", "payload is not canonical")
    return hashlib.sha256(f"{RELEASE_V3_SIGNATURE_DOMAIN_PREFIX}{role}\0".encode("ascii") + body).digest()


def verify_release_envelope_v3(envelope: Any, trust: dict[str, Any], role: str) -> Any:
    """Verify protocol, role, group, owner root and BOTH signatures; return the payload."""
    validate_release_policy_v3_trust(trust)
    if role not in RELEASE_V3_ROLES:
        _refuse("wrong_role")
    e = _record(envelope)
    _fields(e, ("protocol", "role", "groupId", "ownerRootSha256", "payload", "signatures"))
    if e["protocol"] != RELEASE_V3_ENVELOPE_PROTOCOL:
        _refuse("contract_invalid", "not a release envelope v3")
    if e["role"] != role:
        _refuse("wrong_role")
    if e["groupId"] != trust["groupId"]:
        _refuse("wrong_group")
    if e["ownerRootSha256"] != trust["ownerRootSha256"]:
        _refuse("wrong_owner_root")
    signatures = e["signatures"]
    if not isinstance(signatures, list) or len(signatures) != len(RELEASE_V3_KEY_IDS):
        _refuse("signature_invalid", "exactly two signatures are required")
    message = release_envelope_v3_message(role, trust["groupId"], trust["ownerRootSha256"], e["payload"])
    for index, entry in enumerate(signatures):
        signature = _record(entry)
        _fields(signature, ("keyId", "signature"))
        key = trust["keys"][index]
        if signature["keyId"] != key["keyId"] or not isinstance(signature["signature"], str) \
                or not _HEX64.match(signature["signature"]):
            _refuse("signature_invalid", "signers must be usb then laptop with 64-byte lowercase hex signatures")
        try:
            VerifyKey(bytes.fromhex(key["publicKey"])).verify(message, bytes.fromhex(signature["signature"]))
        except (BadSignatureError, ValueError):
            _refuse("signature_invalid", f"{key['keyId']} signature does not verify")
    return e["payload"]


def validate_release_policy_v3_tcb_grace(raw: Any, issued_at_ms: int) -> dict[str, Any]:
    """The backend tcbGraceSchema plus its payload window rule. Returns a copy.

    Parsed so a policy carrying a grace does not refuse the whole feed; it does
    NOT relax customer verification, which keeps requiring UpToDate.
    """
    g = _record(raw)
    _fields(g, ("statuses", "advisoryIds", "notAfterMs"))
    statuses = g["statuses"]
    if not isinstance(statuses, list) or len(statuses) > len(RELEASE_V3_GRACE_TCB_STATUSES) \
            or any(not isinstance(s, str) or s not in RELEASE_V3_GRACE_TCB_STATUSES for s in statuses) \
            or not _ascending(statuses):
        _refuse("contract_invalid", "tcbGrace.statuses must be sorted, unique grace statuses")
    advisories = g["advisoryIds"]
    if not isinstance(advisories, list) or not 1 <= len(advisories) <= MAX_RELEASE_V3_TCB_GRACE_ADVISORIES \
            or any(not isinstance(a, str) or not _ADVISORY_ID.match(a) for a in advisories) \
            or not _ascending(advisories):
        _refuse("contract_invalid", "tcbGrace.advisoryIds must be 1..64 sorted, unique Intel advisory ids")
    not_after = _safe_integer(g["notAfterMs"], 1)
    if not_after <= issued_at_ms or not_after - issued_at_ms > MAX_RELEASE_V3_TCB_GRACE_MS:
        _refuse("contract_invalid", "tcbGrace must end after issuedAtMs and within 90 days of it")
    return {"statuses": list(statuses), "advisoryIds": list(advisories), "notAfterMs": not_after}


def _validate_checkpoint(checkpoint: Any) -> None:
    c = _record(checkpoint)
    _fields(c, ("sequence", "policySha256", "revokedTuples"))
    _safe_integer(c["sequence"], 1)
    if not isinstance(c["policySha256"], str) or not _HEX32.match(c["policySha256"]):
        _refuse("contract_invalid", "invalid checkpoint digest")
    _hex32_list(c["revokedTuples"], MAX_RELEASE_V3_REVOKED_TUPLES)


def check_release_policy_v3_successor(trust: dict[str, Any], previous: dict[str, Any] | None,
                                      next_: dict[str, Any]) -> None:
    """Refuse a sequence below max(minimum, held), a fork, or a dropped revocation."""
    if previous is not None:
        _validate_checkpoint(previous)
    floor = max(trust["minimumPolicySequence"], previous["sequence"] if previous else 0)
    if next_["sequence"] < floor:
        _refuse("policy_rollback", f"sequence {next_['sequence']} < {floor}")
    if previous is None:
        return
    if next_["sequence"] == previous["sequence"]:
        if next_["policySha256"] != previous["policySha256"]:
            _refuse("policy_fork", f"sequence {next_['sequence']}")
        return
    kept = set(next_["revokedTuples"])
    if any(digest not in kept for digest in previous["revokedTuples"]):
        _refuse("revocation_reversed")


def verify_release_policy_v3(envelope: Any, trust: dict[str, Any],
                             previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Verify a ``release-policy`` envelope and, when a checkpoint is held, that
    this policy may follow it. Pure: no clock, no network, no storage."""
    payload = verify_release_envelope_v3(envelope, trust, "release-policy")
    p = _record(payload)
    _fields(p, [*_PAYLOAD_FIELDS, *(name for name in _OPTIONAL_PAYLOAD_FIELDS if name in p)])
    # SDK-local until the backend schema carries it (see VERIFYING.md).
    if "requireGcePzid" in p and type(p["requireGcePzid"]) is not bool:
        _refuse("contract_invalid", "requireGcePzid must be boolean")
    if p["protocol"] != RELEASE_V3_DIGEST_PROTOCOL or p["kind"] != RELEASE_V3_POLICY_KIND:
        _refuse("contract_invalid", "not a release policy")
    if _identifier(p["deploymentId"]) != trust["deploymentId"]:
        _refuse("wrong_deployment")
    sequence = _safe_integer(p["sequence"], 1)
    issued_at_ms = _safe_integer(p["issuedAtMs"], 1)
    tcb_grace = validate_release_policy_v3_tcb_grace(p["tcbGrace"], issued_at_ms) if "tcbGrace" in p else None
    tuples_raw = p["tuples"]
    if not isinstance(tuples_raw, list) or not 1 <= len(tuples_raw) <= MAX_RELEASE_V3_TUPLES:
        _refuse("contract_invalid", "invalid tuple count")
    tuples: list[dict[str, Any]] = []
    for index, entry in enumerate(tuples_raw):
        try:
            tuple_ = validate_gateway_measured_tuple_v3(entry, index)
        except GatewayPolicyError as exc:
            _refuse("contract_invalid", str(exc))
        tuples.append({**tuple_, "tupleDigest": release_tuple_digest(tuple_)})
    if len({t["tupleId"] for t in tuples}) != len(tuples):
        _refuse("contract_invalid", "duplicate tupleId")
    revoked = _hex32_list(p["revokedTuples"], MAX_RELEASE_V3_REVOKED_TUPLES)
    if not _ascending(revoked):
        _refuse("contract_invalid", "revokedTuples must be sorted and unique")
    revoked_generations = _hex32_list(p["revokedGenerations"], 4096)
    minimum_generation_revision = _safe_integer(p["minimumGenerationRevision"], 1)
    max_evidence_age_ms = _safe_integer(p["maxEvidenceAgeMs"], 1_000, 300_000)
    if p["tcbStatus"] != "UpToDate":
        _refuse("contract_invalid", "tcbStatus must be UpToDate")
    if any(t["tupleDigest"] in set(revoked) for t in tuples):
        _refuse("revoked_tuple_approved")
    policy_sha = release_policy_sha256(payload)
    check_release_policy_v3_successor(trust, previous,
                                      {"sequence": sequence, "policySha256": policy_sha, "revokedTuples": revoked})
    verified: dict[str, Any] = {
        "deploymentId": trust["deploymentId"], "groupId": trust["groupId"],
        "ownerRootSha256": trust["ownerRootSha256"], "sequence": sequence, "issuedAtMs": issued_at_ms,
        "policySha256": policy_sha, "tuples": tuples, "revokedTuples": revoked,
        "revokedGenerations": revoked_generations, "minimumGenerationRevision": minimum_generation_revision,
        "maxEvidenceAgeMs": max_evidence_age_ms, "tcbStatus": "UpToDate",
    }
    if tcb_grace is not None:
        verified["tcbGrace"] = tcb_grace
    if "requireGcePzid" in p:
        verified["requireGcePzid"] = p["requireGcePzid"]
    return verified


def release_policy_v3_gateway_policy(verified: dict[str, Any], origins: list[str]) -> GatewayMeasurementPolicy:
    """The fixed gcp-tdx-native floor; only tuples, revocations and evidence age come from the policy."""
    release: dict[str, Any] = {
        "ownerRootSha256": verified["ownerRootSha256"], "deploymentId": verified["deploymentId"],
        "sequence": verified["sequence"], "policySha256": verified["policySha256"],
        "tuples": [{k: copy.deepcopy(v) for k, v in t.items() if k != "tupleDigest"} for t in verified["tuples"]],
        "revokedTuples": list(verified["revokedTuples"]),
    }
    if "requireGcePzid" in verified:
        release["requireGcePzid"] = verified["requireGcePzid"]
    policy = GatewayMeasurementPolicy(
        source=f"anonrouter-release-policy-v3:{verified['deploymentId']}:{verified['policySha256']}",
        version=f"release-policy-v3/{verified['sequence']}",
        origins=[canonical_gateway_origin(o) for o in origins],
        app_ids=[], compose_hashes=[], release_ids=[],
        require_in_tee_tls=True, require_private_logs=True, require_digest_pinned_images=True,
        require_hardware_verified=True, acceptable_tcb_statuses=[verified["tcbStatus"]],
        require_evidence_expiry=True, max_evidence_age_ms=verified["maxEvidenceAgeMs"],
        platform_kind="gcp-tdx-native", release_policy_v3=release,
    )
    assert_gateway_platform_security_floor(policy)
    return policy


# -------------------------------------------------------------------------- source


class ReleasePolicyV3Source:
    """Follow the owner-signed release policy feed.

    Only verified policies are cached. A transport failure, redirect or 5xx may
    reuse the last verified policy until ``max_offline_ms`` after the feed last
    confirmed it; any 4xx, malformed answer, bad signature, rollback, fork or
    revocation reversal refuses at once and never falls back to the cache or to
    bundled pins. Every accepted sequence is also checked against a durable
    cross-process high-water mark (``state_store``).
    """

    def __init__(
        self, *, trust: dict[str, Any] | None = None, url: str | None = None, origins: list[str] | None = None,
        refresh_ms: int = 0, max_offline_ms: int = MAX_RELEASE_V3_OFFLINE_MS,
        http_client: httpx.Client | None = None, now: Callable[[], int] | None = None,
        state_store: Callable[[str, dict[str, Any]], None] | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        defaults = packaged_release_policy_v3_authority()
        self.trust = copy.deepcopy(trust if trust is not None else defaults["trust"])
        validate_release_policy_v3_trust(self.trust)
        self.url = url if url is not None else defaults["url"]
        try:
            parsed = httpx.URL(self.url)
        except (httpx.InvalidURL, TypeError):
            _refuse("trust_invalid", "invalid publication URL")
        if parsed.scheme != "https" or parsed.userinfo or parsed.query or parsed.fragment:
            _refuse("trust_invalid", "invalid publication URL")
        requested = origins if origins is not None else defaults["origins"]
        if not isinstance(requested, list) or not requested:
            _refuse("trust_invalid", "no gateway origins")
        self.origins: list[str] = []
        for origin in requested:
            try:
                canonical = canonical_gateway_origin(origin)
            except ValueError:
                _refuse("trust_invalid", "invalid gateway origin")
            if canonical != origin or httpx.URL(canonical).netloc == parsed.netloc:
                _refuse("trust_invalid", "publication must be separate from authorized gateways")
            self.origins.append(canonical)
        self.refresh_ms = _safe_integer(refresh_ms, 0, MAX_RELEASE_V3_REFRESH_MS, "trust_invalid")
        self.max_offline_ms = _safe_integer(max_offline_ms, 1, MAX_RELEASE_V3_OFFLINE_MS, "trust_invalid")
        if checkpoint is not None:
            _validate_checkpoint(checkpoint)
        self.checkpoint = copy.deepcopy(checkpoint)
        self.http = http_client or httpx.Client(timeout=10.0, trust_env=False, follow_redirects=False)
        self._owns_http = http_client is None
        self.now = now or (lambda: int(time.time() * 1000))
        self.state_store = state_store or FileGatewayPolicyStateStore()
        self.authority = f"anonrouter.release-policy-v3/{self.trust['ownerRootSha256']}"
        self._cached: tuple[dict[str, Any], int] | None = None
        self._lock = threading.Lock()

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def _fetch(self) -> Any:
        """The parsed envelope, or the string "offline"."""
        request = httpx.Request("GET", self.url, headers={"accept": "application/json"},
                                extensions={"timeout": {"connect": 10.0, "read": 10.0, "write": 10.0, "pool": 10.0}})
        try:
            response = self.http.send(request, stream=True, auth=None, follow_redirects=False)
        except httpx.HTTPError:
            return "offline"
        try:
            # A redirect is refused like the JavaScript fetch(redirect: "error").
            if response.status_code >= 500 or 300 <= response.status_code < 400:
                return "offline"
            if not response.is_success:
                _refuse("feed_unavailable", f"status {response.status_code}")
            body = bytearray()
            started = time.monotonic()
            try:
                for chunk in response.iter_bytes(16_384):
                    body.extend(chunk)
                    if len(body) > MAX_RELEASE_POLICY_V3_BYTES:
                        _refuse("contract_invalid", "publication too large")
                    if time.monotonic() - started > 10:
                        return "offline"
            except httpx.HTTPError:
                return "offline"
        finally:
            response.close()
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            return _refuse("contract_invalid", "invalid publication JSON")

    def resolve(self, origin: str, *, force_refresh: bool = False) -> dict[str, Any]:
        with self._lock:
            try:
                canonical = canonical_gateway_origin(origin)
            except ValueError:
                _refuse("unauthorized_origin")
            if canonical not in self.origins:
                _refuse("unauthorized_origin")
            if force_refresh or self._cached is None or self.now() - self._cached[1] >= self.refresh_ms:
                envelope = self._fetch()
                if envelope == "offline":
                    if self._cached is None:
                        _refuse("feed_unavailable", "no verified policy is cached")
                else:
                    release = verify_release_policy_v3(envelope, self.trust, self.checkpoint)
                    self.state_store(self.authority, {"sequence": release["sequence"],
                                                      "payloadSha256": release["policySha256"]})
                    self.checkpoint = {"sequence": release["sequence"], "policySha256": release["policySha256"],
                                       "revokedTuples": list(release["revokedTuples"])}
                    self._cached = (release, self.now())
            assert self._cached is not None
            held, confirmed_at = self._cached
            if self.now() - confirmed_at >= self.max_offline_ms:
                _refuse("cache_stale", "the feed has not confirmed the policy within the offline window")
            release = copy.deepcopy(held)
            return {
                "format": "release-policy-v3",
                "policy": release_policy_v3_gateway_policy(release, self.origins),
                "release": release,
                "authority": self.authority,
                "sequence": release["sequence"],
                "payloadSha256": release["policySha256"],
                "confirmedAtMs": confirmed_at,
                # NOT a policy expiry (v3 has none): when this cached approval stops
                # being usable without a new answer from the feed.
                "expiresAtMs": confirmed_at + self.max_offline_ms,
            }
