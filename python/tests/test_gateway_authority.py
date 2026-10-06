"""Shared signature vectors and automatic rotation/refusal tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from anonrouter_confidential.client import ConfidentialClient
from anonrouter_confidential.gateway.authority import (
    SignedGatewayPolicySource,
    packaged_gateway_policy_authority,
    verify_signed_gateway_policy,
)
from anonrouter_confidential.gateway.policy import (
    GatewayPolicyError,
    load_gateway_policy,
)

V = json.loads((Path(__file__).parents[2] / "shared/vectors/gateway-policy-authority.json").read_text())
ROOT, ORIGIN, NOW = V["root"], V["origin"], V["nowMs"]
VALID, NEXT = V["cases"][0]["envelope"], V["cases"][1]["envelope"]

@pytest.mark.parametrize("case", V["cases"], ids=lambda c: c["name"])
def test_signature_vectors(case: dict[str, Any]) -> None:
    if case["accepted"]:
        assert verify_signed_gateway_policy(case["envelope"], ROOT, ORIGIN, NOW)["policy"].require_hardware_verified
    else:
        with pytest.raises((GatewayPolicyError, ValueError)):
            verify_signed_gateway_policy(case["envelope"], ROOT, ORIGIN, NOW)

def test_staged_roots() -> None:
    assert packaged_gateway_policy_authority()["enabled"] is False
    assert packaged_gateway_policy_authority()["threshold"] == 2

def test_rollback_and_equivocation() -> None:
    previous = verify_signed_gateway_policy(NEXT, ROOT, ORIGIN, NOW)
    with pytest.raises(GatewayPolicyError, match="rollback"):
        verify_signed_gateway_policy(VALID, ROOT, ORIGIN, NOW, previous)
    previous["payloadSha256"] = "00" * 32
    with pytest.raises(GatewayPolicyError, match="conflicting"):
        verify_signed_gateway_policy(NEXT, ROOT, ORIGIN, NOW, previous)

def test_separate_publication_and_distinct_keys() -> None:
    root = copy.deepcopy(ROOT)
    root["url"] = ORIGIN + "/policy"
    with pytest.raises(GatewayPolicyError, match="separate"):
        verify_signed_gateway_policy(VALID, root, ORIGIN, NOW)
    root = copy.deepcopy(ROOT)
    root["keys"]["test-1"] = root["keys"]["test-0"]
    with pytest.raises(GatewayPolicyError, match="distinct"):
        verify_signed_gateway_policy(VALID, root, ORIGIN, NOW)

def test_rotation_cache_and_failure_modes() -> None:
    time, answer, status, requests = [NOW], [VALID], [200], []
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        return httpx.Response(status[0], json=answer[0])
    with httpx.Client(transport=httpx.MockTransport(handler), headers={"authorization":"secret"}, cookies={"session":"secret"}) as http:
        s = SignedGatewayPolicySource(authority=ROOT, http_client=http, now=lambda:time[0], state_store=lambda *_: None)
        assert s.resolve(ORIGIN)["sequence"] == 1
        time[0] += 1000; answer[0] = NEXT
        assert s.resolve(ORIGIN)["policy"].version == "next-release"
        time[0] += 1000; status[0] = 503
        assert s.resolve(ORIGIN)["sequence"] == 2
        time[0] += 1000; status[0] = 200
        answer[0] = copy.deepcopy(NEXT)
        answer[0]["signatures"][0]["signature"] = "00" * 64
        with pytest.raises(GatewayPolicyError, match="signature"):
            s.resolve(ORIGIN)
        time[0] = NOW + 10001; status[0] = 503
        with pytest.raises(GatewayPolicyError, match="expired"):
            s.resolve(ORIGIN)
    assert len(requests) == 5

def test_checkpoint_and_store_refusal() -> None:
    previous = verify_signed_gateway_policy(NEXT, ROOT, ORIGIN, NOW)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200,json=VALID))) as http:
        s = SignedGatewayPolicySource(authority=ROOT, http_client=http, now=lambda:NOW, checkpoint=previous, state_store=lambda *_: None)
        with pytest.raises(GatewayPolicyError, match="rollback"):
            s.resolve(ORIGIN)
        def refuse(authority: str, checkpoint: dict[str, Any]) -> None:
            raise ValueError("persisted newer approval")
        s = SignedGatewayPolicySource(authority=ROOT, http_client=http, now=lambda:NOW, state_store=refuse)
        with pytest.raises(ValueError, match="persisted newer"):
            s.resolve(ORIGIN)

def test_client_uses_signed_policy_and_explicit_policy_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("anonrouter_confidential.client.time.time", lambda: NOW / 1000)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200,json=NEXT))) as feed:
        source = SignedGatewayPolicySource(authority=ROOT,http_client=feed,now=lambda:NOW,state_store=lambda *_: None)
        with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200,json={"binding":{},"quote":"bad"}))) as gateway:
            client = ConfidentialClient(base_url=ORIGIN,api_key="local-test",http_client=gateway,gateway_policy_updates=source)
            result = client.verify_gateway()
            assert result["policy"]["origin"] == "signed-release-authority"
            assert result["policy"]["sequence"] == 2
            assert result["verdict"].status == "failed"
            result = client.verify_gateway(policy=load_gateway_policy(json.loads(VALID["payload"])["policy"]))
            assert result["policy"]["origin"] == "caller-supplied"

def test_no_fallback_on_missing_publication() -> None:
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(404))) as feed:
        source = SignedGatewayPolicySource(authority=ROOT,http_client=feed,now=lambda:NOW,state_store=lambda *_: None)
        client = ConfidentialClient(base_url=ORIGIN,api_key="local-test",gateway_policy_updates=source)
        with pytest.raises(GatewayPolicyError, match="publication unavailable"):
            client.verify_gateway()
        client.close()


def test_durable_high_water_mark(tmp_path: Path) -> None:
    from anonrouter_confidential.gateway.state import FileGatewayPolicyStateStore
    first = FileGatewayPolicyStateStore(tmp_path)
    v = verify_signed_gateway_policy(NEXT, ROOT, ORIGIN, NOW)
    first(ROOT["authority"], {"sequence": v["sequence"], "payloadSha256": v["payloadSha256"]})
    with pytest.raises(GatewayPolicyError, match="persisted"):
        FileGatewayPolicyStateStore(tmp_path)(ROOT["authority"], verify_signed_gateway_policy(VALID, ROOT, ORIGIN, NOW))


def test_frequent_reads_and_forced_refresh() -> None:
    time, calls, answer = [NOW], [], [VALID]
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200,json=answer[0])
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        s = SignedGatewayPolicySource(authority=ROOT,http_client=http,now=lambda:time[0],state_store=lambda *_: None)
        s.resolve(ORIGIN); time[0]+=400; s.resolve(ORIGIN); time[0]+=400; s.resolve(ORIGIN)
        assert len(calls)==1
        time[0]+=300; s.resolve(ORIGIN)
        assert len(calls)==2
        answer[0]=NEXT
        assert s.resolve(ORIGIN,force_refresh=True)["sequence"]==2
        assert len(calls)==3


def test_stale_cache_cannot_extend_signed_authority() -> None:
    root=copy.deepcopy(ROOT); root["maxStaleMs"]=1000
    time, available=[NOW], [True]
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200,json=VALID) if available[0] else httpx.Response(503))) as http:
        s=SignedGatewayPolicySource(authority=root,http_client=http,now=lambda:time[0],state_store=lambda *_: None)
        s.resolve(ORIGIN); time[0]+=1001; available[0]=False
        with pytest.raises(GatewayPolicyError,match="stale"):
            s.resolve(ORIGIN)


def test_client_bounded_policy_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    from anonrouter_confidential.gateway.verify import GatewayVerificationResult
    from anonrouter_confidential.verify.types import AttestationCheck
    monkeypatch.setattr("anonrouter_confidential.client.time.time",lambda:NOW/1000)
    drift=GatewayVerificationResult(status="failed",verification_level="unverified",reason="compose_hash_pinned",
        checks=[AttestationCheck("quote_signature_chain",True,True),AttestationCheck("compose_hash_pinned",False,True)],
        binding=None,app_compose=None,measurements=None,tcb_status=None,
        policy_source="test",policy_version="test",verified_at_ms=NOW)
    verified_calls=[]
    def verify(*args: Any, **kwargs: Any) -> GatewayVerificationResult:
        verified_calls.append(kwargs)
        return drift
    monkeypatch.setattr("anonrouter_confidential.client.verify_gateway_attestation",verify)
    answers=[VALID,NEXT]
    with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=answers.pop(0)))) as feed:
        source=SignedGatewayPolicySource(authority=ROOT,http_client=feed,now=lambda:NOW,state_store=lambda *_: None)
        with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(200,json={"binding":{},"quote":"bad"}))) as gateway:
            client=ConfidentialClient(base_url=ORIGIN,api_key="local-test",http_client=gateway,gateway_policy_updates=source)
            result=client.verify_gateway()
            assert len(verified_calls)==2
            assert result["policy"]["sequence"]==2
            assert result["verdict"].status=="failed"
            assert verified_calls[-1]["policy"].version=="next-release"
