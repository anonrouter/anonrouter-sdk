"""Owner-signed release policy v3: Python parity with the JavaScript SDK.

Loads shared/vectors/release-policy-v3.json, exactly as the JS suite does, and
the shared PZID vectors. The backend section comes from the AnonRouter backend's
own implementation. Everything is synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from anonrouter_confidential.gateway.gce_pzid import (
    gce_instance_from_mr_owner,
    gce_pzid_digest_hex,
    gce_pzid_payload,
    is_gce_uint64,
    parse_gce_pzid,
)
from anonrouter_confidential.gateway.release_v3 import (
    ReleasePolicyV3Error,
    ReleasePolicyV3Source,
    packaged_release_policy_v3_authority,
    release_envelope_v3_message,
    release_owner_root_sha256,
    release_policy_v3_gateway_policy,
    validate_release_policy_v3_trust,
    verify_release_policy_v3,
)
from anonrouter_confidential.gateway.release_v3_canonical import (
    release_policy_sha256,
    release_tuple_digest,
)
from anonrouter_confidential.gateway.verify import verify_gateway_attestation

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "shared" / "vectors" / "release-policy-v3.json").read_text())
PZID = json.loads((ROOT / "shared" / "vectors" / "gce-pzid.json").read_text())
TRUST = VECTORS["trust"]
KAT = VECTORS["backendKat"]


class _Chain:
    implementation = "vector-stub"

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str]:
        return True, "UpToDate"


def _refusal(run: Any) -> str:
    with pytest.raises(ReleasePolicyV3Error) as info:
        run()
    return info.value.code


# ------------------------------------------------------------------ backend KAT


def test_backend_owner_root_tuple_digests_and_messages() -> None:
    trust = KAT["trust"]
    assert release_owner_root_sha256(trust) == trust["ownerRootSha256"]
    for tuple_ in KAT["policy"]["envelope"]["payload"]["tuples"]:
        assert release_tuple_digest(tuple_) == KAT["tupleDigests"][tuple_["tupleId"]]
    for signed in (KAT["policy"], KAT["successor"]):
        e = signed["envelope"]
        message = release_envelope_v3_message("release-policy", e["groupId"], e["ownerRootSha256"], e["payload"])
        assert message.hex() == signed["signingMessage"]


def test_backend_signed_policy_and_successor() -> None:
    trust = KAT["trust"]
    first = verify_release_policy_v3(KAT["policy"]["envelope"], trust)
    assert first["policySha256"] == KAT["policy"]["payloadSha256"]
    nxt = verify_release_policy_v3(KAT["successor"]["envelope"], trust, {
        "sequence": first["sequence"], "policySha256": first["policySha256"], "revokedTuples": first["revokedTuples"]})
    assert nxt["policySha256"] == KAT["successor"]["payloadSha256"]


def test_backend_tcb_grace_digest() -> None:
    assert release_policy_sha256(KAT["tcbGrace"]["payload"]) == KAT["tcbGrace"]["policySha256"]


# ------------------------------------------------------------------ shared cases


@pytest.mark.parametrize("case", VECTORS["policyCases"], ids=lambda c: c["name"])
def test_policy_case(case: dict[str, Any]) -> None:
    trust = {**TRUST, "minimumPolicySequence": case.get("minimumPolicySequence", 1)}
    previous = case.get("previous")
    expected = case["expected"]
    if "refusal" in expected:
        assert _refusal(lambda: verify_release_policy_v3(case["envelope"], trust, previous)) == expected["refusal"]
        return
    v = verify_release_policy_v3(case["envelope"], trust, previous)
    assert {
        "sequence": v["sequence"], "policySha256": v["policySha256"],
        "tupleDigests": [t["tupleDigest"] for t in v["tuples"]], "revokedTuples": v["revokedTuples"],
        "tcbGrace": v.get("tcbGrace"), "requireGcePzid": v.get("requireGcePzid"),
    } == expected["ok"]


@pytest.mark.parametrize("case", VECTORS["attestationCases"], ids=lambda c: c["name"])
def test_attestation_case(case: dict[str, Any]) -> None:
    e = VECTORS["expectations"]
    policy = release_policy_v3_gateway_policy(verify_release_policy_v3(case["envelope"], TRUST), [e["origin"]])
    verdict = verify_gateway_attestation(
        case["evidence"], nonce=e["nonce"], origin=e["origin"], policy=policy, now_ms=e["nowMs"],
        observed_tls_spki_sha256=e["observedTlsSpki"], observed_tls_spki_supplied=True,
        chain_verifier=_Chain(), observed_on_retained_connection=True,
    )
    assert {
        "status": verdict.status, "verificationLevel": verdict.verification_level, "reason": verdict.reason,
        "instanceIdentity": verdict.instance_identity, "gceInstance": verdict.gce_instance,
        "checks": [[c.name, c.passed, c.required] for c in verdict.checks],
    } == case["expected"]


# ------------------------------------------------------------------ PZID vectors


def test_pzid_vectors() -> None:
    for vector in PZID["vectors"]:
        payload = gce_pzid_payload(vector)
        assert payload == vector["payload"]
        assert gce_pzid_digest_hex(payload) == vector["mrOwner"]
    for vector in [v for v in PZID["vectors"] if v["projectNumber"] != "0"]:
        fields = {"projectNumber": vector["projectNumber"], "zone": vector["zone"], "instanceId": vector["instanceId"]}
        assert parse_gce_pzid(vector["payload"]) == fields
        assert gce_instance_from_mr_owner(vector["payload"], vector["mrOwner"].upper()) == fields
        assert gce_instance_from_mr_owner(vector["payload"], "00" * 48) is None
    zero = next(v for v in PZID["vectors"] if v["projectNumber"] == "0")
    assert parse_gce_pzid(zero["payload"]) is None
    assert not is_gce_uint64("18446744073709551616")
    assert is_gce_uint64("18446744073709551615")


# ------------------------------------------------------------- packaged root


def test_packaged_root_has_owner_keys_and_floor_but_no_image_pins() -> None:
    authority = packaged_release_policy_v3_authority()
    validate_release_policy_v3_trust(authority["trust"])
    assert authority["trust"]["minimumPolicySequence"] == 6
    assert authority["origins"] == ["https://api.anonrouter.ai"]
    assert authority["url"] == "https://anonrouter.ai/.well-known/anonrouter-content-release-v3.json"
    assert sorted(authority["trust"]) == ["deploymentId", "groupId", "keys", "minimumPolicySequence", "ownerRootSha256"]
    assert "tuples" not in json.dumps(authority)


# ------------------------------------------------------------------ the source


def _envelope(index: int) -> Any:
    return next(c for c in VECTORS["policyCases"] if c["name"] == ["sequence 1 with two tuples",
                                                                    "sequence 2 revokes tuple A"][index])["envelope"]


class _States:
    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []

    def __call__(self, authority: str, checkpoint: dict[str, Any]) -> None:
        if self.seen and checkpoint["sequence"] < self.seen[-1]["sequence"]:
            raise ValueError("rollback")
        self.seen.append(dict(checkpoint))


def _source(responses: list[Any], clock: list[int], states: _States | None = None) -> ReleasePolicyV3Source:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, int):
            return httpx.Response(item)
        return httpx.Response(200, json=item)
    return ReleasePolicyV3Source(
        trust=TRUST, url="https://policy.example/release.json", origins=["https://content.gcp.example"],
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), now=lambda: clock[0],
        state_store=states or _States())


def test_source_advances_and_refuses_rollback_in_session() -> None:
    clock = [1_000]
    states = _States()
    source = _source([_envelope(0), _envelope(1), _envelope(0)], clock, states)
    assert source.resolve("https://content.gcp.example")["sequence"] == 1
    approval = source.resolve("https://content.gcp.example")
    assert approval["sequence"] == 2
    assert approval["policy"].release_policy_v3["revokedTuples"] == approval["release"]["revokedTuples"]
    assert _refusal(lambda: source.resolve("https://content.gcp.example")) == "policy_rollback"
    assert [s["sequence"] for s in states.seen] == [1, 2]


def test_source_offline_window_and_refusals() -> None:
    clock = [1_000]
    source = _source([_envelope(0), httpx.ConnectError("down"), 503, 404], clock)
    first = source.resolve("https://content.gcp.example")
    clock[0] += 1_000
    assert source.resolve("https://content.gcp.example")["confirmedAtMs"] == first["confirmedAtMs"]
    clock[0] = first["confirmedAtMs"] + 3_600_000
    assert _refusal(lambda: source.resolve("https://content.gcp.example")) == "cache_stale"
    assert _refusal(lambda: source.resolve("https://content.gcp.example")) == "feed_unavailable"
    assert _refusal(lambda: source.resolve("https://other.example")) == "unauthorized_origin"


def test_source_without_a_cached_policy_refuses_when_offline() -> None:
    source = _source([httpx.ConnectError("down")], [1_000])
    assert _refusal(lambda: source.resolve("https://content.gcp.example")) == "feed_unavailable"


def test_source_refuses_a_publication_on_a_gateway_host() -> None:
    with pytest.raises(ReleasePolicyV3Error) as info:
        ReleasePolicyV3Source(trust=TRUST, url="https://content.gcp.example/policy.json",
                              origins=["https://content.gcp.example"], state_store=_States())
    assert info.value.code == "trust_invalid"


def test_source_requires_the_pinned_root() -> None:
    other = {**TRUST, "ownerRootSha256": "ab" * 32}
    with pytest.raises(ReleasePolicyV3Error) as info:
        ReleasePolicyV3Source(trust=other, state_store=_States())
    assert info.value.code == "wrong_owner_root"
