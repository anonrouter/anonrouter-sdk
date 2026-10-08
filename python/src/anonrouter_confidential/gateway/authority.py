"""Signed release approvals. Transport cannot choose keys or weaken checks.

No private keys, credentials or inference content enter this module. The
packaged roots are staged until the first real publication is accepted.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

import httpx
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .binding import canonical_gateway_origin
from .policy import (
    GATEWAY_PLATFORM_QUALIFIED,
    GatewayMeasurementPolicy,
    GatewayPolicyError,
    assert_gateway_platform_security_floor,
    gateway_policy_platform_kind,
    load_gateway_policy,
)
from .state import FileGatewayPolicyStateStore

GATEWAY_POLICY_DOMAIN = "anonrouter.gateway-policy-signature/v1\n"
MAX_GATEWAY_POLICY_BYTES = 262_144


def _fail(why: str) -> Any:
    raise GatewayPolicyError(f"signed gateway policy: {why}")


def _record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("expected object")
    return value  # type: ignore[no-any-return]


def _fields(value: dict[str, Any], names: list[str]) -> None:
    if set(value) != set(names):
        _fail("unexpected or missing fields")


def _integer(value: Any, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 9_007_199_254_740_991:
        _fail("invalid integer")
    return value  # type: ignore[no-any-return]


def canonical_gateway_policy_json(value: Any) -> str:
    """ASCII strings and safe integers: same exact signed bytes in both SDKs."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if type(value) is int:
        return str(_integer(value))
    if isinstance(value, str):
        if not value.isascii():
            _fail("non-ASCII string")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_gateway_policy_json(x) for x in value) + "]"
    obj = _record(value)
    return "{" + ",".join(
        canonical_gateway_policy_json(k) + ":" + canonical_gateway_policy_json(obj[k])
        for k in sorted(obj)
    ) + "}"


def packaged_gateway_policy_authority() -> dict[str, Any]:
    return json.loads(resources.files("anonrouter_confidential").joinpath(
        "gateway_policy_authority.json"
    ).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def validate_gateway_policy_authority(root: dict[str, Any]) -> None:
    if (root.get("schema") != "anonrouter.gateway-policy-authority/v1"
            or not isinstance(root.get("authority"), str) or not root["authority"]
            or type(root.get("enabled")) is not bool):
        _fail("invalid authority")
    url = urlsplit(root["url"])
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment):
        _fail("invalid publication URL")
    origins = root.get("origins")
    if (not isinstance(origins, list) or not origins
            or any(canonical_gateway_origin(o) != o or urlsplit(o).netloc == url.netloc
                   for o in origins)):
        _fail("publication must be separate from authorized gateways")
    _integer(root["threshold"], 2)
    _integer(root["minSequence"], 1)
    _integer(root["maxLifetimeMs"], 1)
    _integer(root["refreshMs"], 1)
    _integer(root["maxStaleMs"], root["refreshMs"])
    if (root["maxLifetimeMs"] > 604_800_000 or root["refreshMs"] > 300_000
            or root["maxStaleMs"] > 7_200_000):
        _fail("excessive lifetime/refresh")
    keys = list(_record(root["keys"]).values())
    if (len(keys) < root["threshold"] or any(
            not isinstance(k, str) or not re.fullmatch(r"[0-9a-f]{64}", k) for k in keys)
            or len(set(keys)) != len(keys)):
        _fail("invalid distinct signing keys")


def assert_gateway_policy_security_floor(policy: GatewayMeasurementPolicy) -> None:
    """The per-platform-kind floor (see policy.py). Legacy policies keep exactly
    their historical floor; tuple-form policies are also re-validated whole."""
    try:
        assert_gateway_platform_security_floor(policy)
    except GatewayPolicyError as exc:
        _fail(str(exc).removeprefix("policy security floor: "))


def verify_signed_gateway_policy(
    envelope: Any, root: dict[str, Any], origin: str, now_ms: int,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_gateway_policy_authority(root)
    _integer(now_ms)
    e = _record(envelope)
    _fields(e, ["schema", "payload", "signatures"])
    if (e["schema"] != "anonrouter.gateway-policy-envelope/v1"
            or not isinstance(e["payload"], str)
            or len(e["payload"].encode("utf-8")) > MAX_GATEWAY_POLICY_BYTES):
        _fail("invalid envelope")
    try:
        raw = _record(json.loads(e["payload"]))
    except (ValueError, RecursionError):
        _fail("invalid payload JSON")
    if canonical_gateway_policy_json(raw) != e["payload"]:
        _fail("noncanonical payload")
    _fields(raw, ["schema", "authority", "sequence", "issuedAtMs", "expiresAtMs",
                  "manifestSha256", "policy"])
    if (raw["schema"] != "anonrouter.gateway-policy/v1" or raw["authority"] != root["authority"]
            or not isinstance(raw["manifestSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", raw["manifestSha256"])):
        _fail("wrong authority/manifest")
    sequence = _integer(raw["sequence"], root["minSequence"])
    issued = _integer(raw["issuedAtMs"])
    expires = _integer(raw["expiresAtMs"])
    if (issued > now_ms or expires <= now_ms or expires <= issued
            or expires - issued > root["maxLifetimeMs"]):
        _fail("expired, future or excessive validity")
    digest = hashlib.sha256(e["payload"].encode("utf-8")).hexdigest()
    if previous and (sequence < previous["sequence"] or (
            sequence == previous["sequence"] and digest != previous["payloadSha256"])):
        _fail("rollback or conflicting sequence")
    if not isinstance(e["signatures"], list) or len(e["signatures"]) > 16:
        _fail("invalid signatures")
    accepted: list[str] = []
    for item in e["signatures"]:
        s = _record(item)
        _fields(s, ["keyId", "signature"])
        if (not isinstance(s["keyId"], str) or s["keyId"] not in root["keys"]
                or s["keyId"] in accepted or not isinstance(s["signature"], str)
                or not re.fullmatch(r"[0-9a-f]{128}", s["signature"])):
            _fail("unknown/duplicate signer or malformed signature")
        try:
            VerifyKey(bytes.fromhex(root["keys"][s["keyId"]])).verify(
                (GATEWAY_POLICY_DOMAIN + e["payload"]).encode("utf-8"), bytes.fromhex(s["signature"])
            )
        except (BadSignatureError, ValueError):
            _fail("invalid signature")
        accepted.append(s["keyId"])
    if len(accepted) < root["threshold"]:
        _fail("signature threshold not met")
    policy = load_gateway_policy(raw["policy"])
    assert_gateway_policy_security_floor(policy)
    # Custodian signatures cannot qualify a platform: an unqualified boot chain is
    # refused here until a reviewed SDK release qualifies its kind.
    if not GATEWAY_PLATFORM_QUALIFIED.get(gateway_policy_platform_kind(policy), False):
        _fail("platform kind is not qualified for signed approval")
    canonical = canonical_gateway_origin(origin)
    if (canonical not in root["origins"] or canonical not in policy.origins
            or any(o not in root["origins"] for o in policy.origins)):
        _fail("unauthorized origin")
    if policy.source != "anonrouter-release-manifest-sha256:" + raw["manifestSha256"]:
        _fail("manifest binding mismatch")
    return {"policy": policy, "sequence": sequence, "payloadSha256": digest,
            "authority": root["authority"], "manifestSha256": raw["manifestSha256"],
            "issuedAtMs": issued, "expiresAtMs": expires, "acceptedKeyIds": accepted}


class SignedGatewayPolicySource:
    """Refresh verified approvals; never fall back to bundled pins.

    Session and durable restart rollback checks are enforced by default. A custom
    ``state_store`` must implement atomic durable compare-and-set. It receives only
    authority, sequence and public payload hash, and must raise on rollback.
    """
    def __init__(
        self, *, authority: dict[str, Any] | None = None,
        http_client: httpx.Client | None = None, now: Callable[[], int] | None = None,
        state_store: Callable[[str, dict[str, Any]], None] | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        self.root = copy.deepcopy(authority or packaged_gateway_policy_authority())
        validate_gateway_policy_authority(self.root)
        self.http = http_client or httpx.Client(timeout=10.0, trust_env=False)
        self._owns_http = http_client is None
        self.now = now or (lambda: int(time.time() * 1000))
        self.state_store = state_store or FileGatewayPolicyStateStore()
        self.checkpoint = copy.deepcopy(checkpoint)
        self.cached: Any = None
        self.refreshed_at = 0
        self.lock = threading.Lock()

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def resolve(self, origin: str, *, force_refresh: bool = False) -> dict[str, Any]:
        with self.lock:
            now = self.now()
            envelope = self.cached
            refreshed_at = self.refreshed_at
            if force_refresh or self.cached is None or now - self.refreshed_at >= self.root["refreshMs"]:
                request = httpx.Request("GET", self.root["url"], headers={"accept": "application/json"},
                    extensions={"timeout": {"connect": 10.0, "read": 10.0, "write": 10.0, "pool": 10.0}})
                try:
                    response = self.http.send(request, stream=True, auth=None, follow_redirects=False)
                    try:
                        if response.is_success:
                            body = bytearray()
                            started = time.monotonic()
                            for chunk in response.iter_bytes(16_384):
                                body.extend(chunk)
                                if len(body) > MAX_GATEWAY_POLICY_BYTES:
                                    _fail("publication too large")
                                if time.monotonic() - started > 10:
                                    _fail("publication timed out")
                            try:
                                envelope = json.loads(body.decode("utf-8"))
                            except (ValueError, UnicodeError, RecursionError):
                                _fail("invalid publication JSON")
                            refreshed_at = self.now()
                        elif self.cached is None or response.status_code < 500:
                            _fail("publication unavailable")
                    finally:
                        response.close()
                except httpx.HTTPError:
                    if self.cached is None:
                        _fail("publication unavailable")
            if self.now() - refreshed_at > self.root["maxStaleMs"]:
                _fail("publication cache too stale")
            verified = verify_signed_gateway_policy(envelope, self.root, origin, self.now(), self.checkpoint)
            checkpoint = {"sequence": verified["sequence"], "payloadSha256": verified["payloadSha256"]}
            self.state_store(self.root["authority"], checkpoint)
            self.checkpoint = checkpoint
            self.cached = copy.deepcopy(envelope)
            self.refreshed_at = refreshed_at
            return verify_signed_gateway_policy(envelope, self.root, origin, self.now(), self.checkpoint)
