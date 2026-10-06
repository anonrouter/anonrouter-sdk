"""Current public provider contract and publication/key substitution controls."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from anonrouter_confidential.client import ConfidentialClient, ConfidentialError
from anonrouter_confidential.verify.registry import verify_raw_evidence

FIXTURE = json.loads((Path(__file__).parents[2] / "shared/vectors/near-authority.json").read_text())


def verdict(document=None, model=None, nonce=None):
    client = ConfidentialClient(api_key="synthetic")
    expectations = client._expectations("other", model or FIXTURE["upstreamModel"], nonce or FIXTURE["nonce"], "e2ee")
    expectations.now_ms = FIXTURE["now"]
    return verify_raw_evidence("other", document if document is not None else FIXTURE["evidence"], expectations)


def test_current_public_report_has_an_honest_provider_attested_ceiling():
    result = verdict()
    assert result.status == "ok"
    assert result.verification_level == "provider-attested"


MUTATIONS = [
    (["anonrouter_release_collateral"], None),
    (["anonrouter_release_collateral", "github", 0, "repository"], "attacker/repo"),
    (["anonrouter_release_collateral", "github", 0, "files", 0, "sha256"], "00" * 32),
    (["anonrouter_release_collateral", "dstackImages", 0, "measurements", 0, "rtmr2"], "11" * 48),
    (["anonrouter_release_collateral", "onchain", 0, "composeHashAllowed"], False),
    (["anonrouter_release_collateral", "onchain", 0, "kms"], "0x00"),
    (["anonrouter_release_collateral", "onchain", 0, "chainId"], 1),
    (["anonrouter_release_collateral", "github", 0, "fetchedAtMs"], 0),
    (["anonrouter_release_collateral", "githubReleases", 0, "images"], []),
    (["compose_manager_attestation", "actions", 0, "image"], "attacker/image"),
    (["event_log"], []),
    (["signing_public_key"], "11" * 32),
    (["signing_algo"], "ecdsa"),
    (["nvidia_payload"], None),
    (["anonrouter_release_collateral", "github"], {}),
]


@pytest.mark.parametrize(("path", "value"), MUTATIONS)
def test_substitution_fails_closed(path, value):
    document = copy.deepcopy(FIXTURE["evidence"])
    cursor = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    assert verdict(document).status == "failed"


def test_unpublished_commit_fails_closed():
    document = copy.deepcopy(FIXTURE["evidence"])
    publication = document["anonrouter_release_collateral"]["github"][0]
    publication["tags"], publication["defaultBranchAncestors"] = {}, []
    assert verdict(document).status == "failed"


def test_gpu_nonce_substitution_fails_closed():
    document = copy.deepcopy(FIXTURE["evidence"])
    gpu = json.loads(document["nvidia_payload"])
    gpu["nonce"] = "00" * 32
    document["nvidia_payload"] = json.dumps(gpu)
    assert verdict(document).status == "failed"


def test_unknown_model_and_wrong_nonce_are_refused():
    assert verdict(model="unknown/model").status == "failed"
    assert verdict(nonce="ab" * 32).status == "failed"


def test_chat_preserves_public_provider_in_paid_ticket_body_and_protocol_headers(monkeypatch):
    # Entirely synthetic transport: no network, paid ticket, or provider request.
    monkeypatch.setattr("anonrouter_confidential.client.os.urandom", lambda n: bytes.fromhex(FIXTURE["nonce"])[:n])
    monkeypatch.setattr("anonrouter_confidential.verify.checks.time.time", lambda: FIXTURE["now"] / 1000)
    monkeypatch.setattr("anonrouter_confidential.verify.near.time.time", lambda: FIXTURE["now"] / 1000)
    requests = []

    def handle(request):
        requests.append(request)
        if request.url.path == "/v1/tee/attestation":
            return httpx.Response(200, json={"provider": "other", "model": FIXTURE["upstreamModel"],
                "upstream_model": FIXTURE["upstreamModel"], "privacy_class": "e2ee", "protocol": "near-v2",
                "evidence": FIXTURE["evidence"]})
        return httpx.Response(200, json={"ticket": "synthetic"})

    http = httpx.Client(transport=httpx.MockTransport(handle))
    client = ConfidentialClient(api_key="synthetic", http_client=http)
    observed = {}
    monkeypatch.setattr(client, "_consume_sse", lambda body, headers, decrypt: observed.update(body=body, headers=headers) or {"content": "synthetic"})
    client.chat(FIXTURE["upstreamModel"], "other", [{"role": "user", "content": "canary"}], 8)
    for request in requests:
        if request.url.path in {"/v1/inference/attestation-tickets", "/v1/inference/tickets"}:
            assert json.loads(request.content)["provider"] == "other"
    assert observed["body"]["provider"] == "other"
    assert observed["headers"]["x-anonrouter-e2ee-provider"] == "other"
    assert observed["headers"]["x-encryption-version"] == "2"
    assert "authorization" not in observed["headers"]
    assert observed["body"]["messages"][0]["content"] != "canary"


def test_chat_refuses_a_substituted_key_before_minting_an_inference_ticket(monkeypatch):
    monkeypatch.setattr("anonrouter_confidential.client.os.urandom", lambda n: bytes.fromhex(FIXTURE["nonce"])[:n])
    monkeypatch.setattr("anonrouter_confidential.verify.checks.time.time", lambda: FIXTURE["now"] / 1000)
    monkeypatch.setattr("anonrouter_confidential.verify.near.time.time", lambda: FIXTURE["now"] / 1000)
    document = copy.deepcopy(FIXTURE["evidence"])
    document["signing_public_key"] = "11" * 32
    paths = []

    def handle(request):
        paths.append(request.url.path)
        if request.url.path != "/v1/tee/attestation":
            return httpx.Response(200, json={"ticket": "synthetic"})
        return httpx.Response(200, json={"provider": "other", "model": FIXTURE["upstreamModel"],
            "upstream_model": FIXTURE["upstreamModel"], "privacy_class": "e2ee", "protocol": "near-v2", "evidence": document})

    client = ConfidentialClient(api_key="synthetic", http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    with pytest.raises(ConfidentialError):
        client.chat(FIXTURE["upstreamModel"], "other", [{"role": "user", "content": "canary"}], 8)
    assert "/v1/inference/tickets" not in paths
