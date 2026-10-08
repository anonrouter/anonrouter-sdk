"""Tuple-form gateway policies: explicit platform kinds, whole release tuples,
GCP same-connection key binding and the unqualified-platform gate.

Mirrors ``js/confidential/test/gateway-release-tuples.test.ts`` over the same
shared vector bytes. Everything is synthetic: no value here is a Google firmware
measurement or an AnonRouter production pin.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from anonrouter_confidential.client import ConfidentialClient
from anonrouter_confidential.errors import ConfidentialError
from anonrouter_confidential.gateway.authority import (
    assert_gateway_policy_security_floor,
    verify_signed_gateway_policy,
)
from anonrouter_confidential.gateway.policy import (
    GATEWAY_PLATFORM_QUALIFIED,
    GatewayMeasurementPolicy,
    GatewayPolicyError,
    gateway_policy_registry,
    load_gateway_policy,
)
from anonrouter_confidential.gateway.verify import verify_gateway_attestation

_VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "shared" / "vectors" / "gateway-release-tuples.json")
    .read_text(encoding="utf-8")
)


class _Stub:
    implementation = "vector-stub"

    def __init__(self, verified: bool, tcb_status: str | None) -> None:
        self._verified, self._tcb_status = verified, tcb_status

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None]:
        return self._verified, self._tcb_status


def _run(case: dict[str, Any], policy: GatewayMeasurementPolicy | None = None) -> Any:
    e = case["expectations"]
    chain = case["chainVerifier"]
    return verify_gateway_attestation(
        case["evidence"],
        nonce=e["nonce"],
        origin=e["origin"],
        policy=policy or load_gateway_policy(case["policy"]),
        now_ms=e["nowMs"],
        observed_tls_spki_sha256=e["observedTlsSpki"]["value"] if e["observedTlsSpki"]["supplied"] else None,
        observed_tls_spki_supplied=bool(e["observedTlsSpki"]["supplied"]),
        observed_on_retained_connection=e["observedOnRetainedConnection"],
        unqualified_platform_pilot=e["unqualifiedPlatformPilot"],
        chain_verifier=_Stub(chain["verified"], chain["tcbStatus"]) if chain else None,
    )


@pytest.mark.parametrize("case", _VECTORS["loadCases"], ids=lambda c: c["name"])
def test_policy_documents(case: dict[str, Any]) -> None:
    if not case["accepted"]:
        with pytest.raises(GatewayPolicyError):
            load_gateway_policy(case["policy"])
        return
    policy = load_gateway_policy(case["policy"])
    assert_gateway_policy_security_floor(policy)
    assert policy.platform is None and policy.key_provider_id is None
    assert policy.release_tuples is not None
    assert policy.release_ids == list(dict.fromkeys(t.release_id for t in policy.release_tuples))


@pytest.mark.parametrize("case", _VECTORS["verifyCases"], ids=lambda c: c["name"])
def test_verdicts(case: dict[str, Any]) -> None:
    result = _run(case)
    tuple_check = next((c for c in result.checks if c.name == "release_tuple_matched"), None)
    assert {
        "status": result.status,
        "verificationLevel": result.verification_level,
        "reason": result.reason,
        "failedRequiredChecks": [c.name for c in result.checks if c.required and not c.passed],
        "unmetAdvisoryChecks": [c.name for c in result.checks if not c.required and not c.passed],
        "releaseTupleDetail": tuple_check.detail if tuple_check else None,
    } == case["expected"]


def test_mutated_policy_fails_its_own_floor() -> None:
    case = _VECTORS["verifyCases"][0]
    weakened = dataclasses.replace(load_gateway_policy(case["policy"]), require_hardware_verified=False)
    result = _run(case, weakened)
    assert result.status == "failed" and result.reason == "policy_security_floor"


def test_tuples_cannot_skip_the_platform_kind() -> None:
    case = _VECTORS["verifyCases"][0]
    without_kind = dataclasses.replace(load_gateway_policy(case["policy"]), platform_kind=None)
    with pytest.raises(GatewayPolicyError, match="explicit platformKind"):
        assert_gateway_policy_security_floor(without_kind)
    assert _run(case, without_kind).reason == "policy_security_floor"


def test_derived_lists_cannot_be_widened() -> None:
    policy = load_gateway_policy(_VECTORS["verifyCases"][0]["policy"])
    widened = dataclasses.replace(policy, release_ids=[*policy.release_ids, "content@unreviewed"])
    with pytest.raises(GatewayPolicyError, match="derived identity"):
        assert_gateway_policy_security_floor(widened)


@pytest.mark.parametrize("case", _VECTORS["signedCases"], ids=lambda c: c["name"])
def test_signed_feed_never_supplies_an_unqualified_platform(case: dict[str, Any]) -> None:
    def verify() -> dict[str, Any]:
        return verify_signed_gateway_policy(
            case["envelope"], _VECTORS["signingRoot"], case["origin"], _VECTORS["nowMs"]
        )

    if case["accepted"]:
        assert verify()["policy"].platform_kind == "phala-dstack-kms"
    else:
        with pytest.raises(GatewayPolicyError, match="not qualified"):
            verify()


def test_gcp_is_not_qualified() -> None:
    assert GATEWAY_PLATFORM_QUALIFIED == {"phala-dstack-kms": True, "gcp-tdx-native": False}


def test_packaged_registry_is_unchanged_single_value_legacy() -> None:
    for entry in gateway_policy_registry():
        p = entry.policy
        assert p.platform_kind is None and p.release_tuples is None and p.platform is not None
        for values in (p.app_ids, p.compose_hashes, p.release_ids, p.platform.mr_td,
                       p.platform.mr_config_id, p.platform.rtmr0, p.platform.rtmr1,
                       p.platform.rtmr2, p.platform.os_image_hash):
            assert len(values) == 1


# ---- client refuses before any request ----------------------------------------

_GCP = load_gateway_policy(_VECTORS["verifyCases"][0]["policy"])
_ORIGIN = _VECTORS["verifyCases"][0]["expectations"]["origin"]


def _unbound() -> tuple[ConfidentialClient, list[str]]:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(500)

    client = ConfidentialClient(
        base_url=_ORIGIN, api_key="synthetic-key", control_base_url="https://control.gcp.example",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return client, seen


def test_standalone_verify_gateway_is_refused_without_a_request() -> None:
    client, seen = _unbound()
    with pytest.raises(ConfidentialError, match="connection binding"):
        client.verify_gateway(policy=_GCP, unqualified_platform_pilot=True)
    assert seen == []


def test_unbound_chat_gated_on_gcp_is_refused_without_a_request() -> None:
    client, seen = _unbound()
    with pytest.raises(ConfidentialError, match="connection binding"):
        client.chat("venice-uncensored", "venice", [{"role": "user", "content": "synthetic-content-canary"}], 8,
                    require_gateway={"policy": _GCP, "unqualified_platform_pilot": True})
    assert seen == []


def test_bound_client_without_pilot_is_refused_before_any_connection() -> None:
    client = ConfidentialClient(
        base_url=_ORIGIN, api_key="synthetic-key", control_base_url="https://control.gcp.example",
        gateway_connection_binding={"mode": "required", "verification": {
            "policy": _GCP, "chain_verifier": _Stub(False, None)}},
    )
    with pytest.raises(ConfidentialError, match="unqualified_platform_pilot"):
        client.chat("venice-uncensored", "venice", [{"role": "user", "content": "synthetic-content-canary"}], 8)


def test_bound_client_refuses_a_non_boolean_pilot_flag() -> None:
    with pytest.raises(ConfidentialError):
        ConfidentialClient(
            base_url=_ORIGIN, api_key="synthetic-key", control_base_url="https://control.gcp.example",
            gateway_connection_binding={"mode": "required", "verification": {
                "policy": _GCP, "chain_verifier": _Stub(False, None), "unqualified_platform_pilot": "yes"}},
        )
