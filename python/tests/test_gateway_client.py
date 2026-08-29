"""Client-level tests for the two-hop verification API.

The point of these is not the crypto (test_gateway_verify.py covers that) but the
WIRING: that hop 1 and hop 2 stay distinct, that a report never implies it covered
a hop it skipped, that chat() refuses to send anything when a required hop fails,
and that a client cannot be pointed at an origin whose attestation could not mean
anything.

Mirrors ``js/confidential/test/client-two-hop.test.ts``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from gateway_fixtures import (
    build_app_compose,
    build_synthetic_event_log,
    build_synthetic_tdx_quote,
    build_vm_config,
)

from anonrouter_confidential.client import ConfidentialClient, ConfidentialError
from anonrouter_confidential.gateway.binding import (
    GATEWAY_BINDING_VERSION,
    gateway_binding_hash,
)
from anonrouter_confidential.gateway.policy import (
    GatewayMeasurementPolicy,
    load_gateway_policy,
)

ORIGIN = "https://gateway.test.invalid"
APP_ID = "0123456789abcdef0123456789abcdef01234567"
INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98"
RELEASE_ID = "anonrouter-tee@test"

MANIFEST, COMPOSE_HASH = build_app_compose()


def gateway_test_policy() -> GatewayMeasurementPolicy:
    return load_gateway_policy(
        {
            "source": "test-suite",
            "version": "1",
            "origins": [ORIGIN],
            "appIds": [APP_ID],
            "composeHashes": [COMPOSE_HASH],
            "releaseIds": [RELEASE_ID],
            "requireInTeeTls": False,
            "requirePrivateLogs": True,
            "requireDigestPinnedImages": True,
            "requireHardwareVerified": False,
            "acceptableTcbStatuses": ["UpToDate"],
            "requireEvidenceExpiry": False,
            "maxEvidenceAgeMs": 300_000,
        }
    )


def gateway_document_for(nonce: str, **overrides: Any) -> dict[str, Any]:
    """Build a gateway document bound to whatever nonce the client actually sent."""
    binding: dict[str, Any] = {
        "v": GATEWAY_BINDING_VERSION,
        "nonce": nonce,
        "app_id": APP_ID,
        "instance_id": INSTANCE_ID,
        "compose_hash": COMPOSE_HASH,
        "release_id": RELEASE_ID,
        "origin": ORIGIN,
        "key_alg": "x25519",
        "public_key": "ab" * 32,
        "transport": "gateway-tls",
        "tls_spki_sha256": None,
    }
    binding.update(overrides)
    log = build_synthetic_event_log(
        app_id=APP_ID, compose_hash=str(binding["compose_hash"]), instance_id=INSTANCE_ID
    )
    return {
        "binding": binding,
        "binding_hash": gateway_binding_hash(binding),
        "quote": build_synthetic_tdx_quote(
            report_data_hex=gateway_binding_hash(binding),
            rtmr0=log.rtmr0,
            rtmr1=log.rtmr1,
            rtmr2=log.rtmr2,
            rtmr3=log.rtmr3,
        ),
        "event_log": log.as_json(),
        "app_compose": MANIFEST,
        "vm_config": build_vm_config(),
        "issued_at_ms": 1_760_000_000_000,
    }


def make_client(
    gateway: str = "ok", *, api_key: str = "ar_test_key"
) -> tuple[ConfidentialClient, list[str], list[dict[str, str]]]:
    """A stub AnonRouter, recording every path it was asked for."""
    paths: list[str] = []
    headers_seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/v1/gateway/attestation":
            headers_seen.append(dict(request.headers))
            if gateway == "unavailable":
                return httpx.Response(
                    503, json={"error": {"type": "gateway_attestation_unavailable"}}
                )
            nonce = request.url.params.get("nonce", "")
            overrides = (
                {"release_id": "anonrouter-tee@unreviewed"} if gateway == "wrong-release" else {}
            )
            return httpx.Response(200, json=gateway_document_for(nonce, **overrides))
        if request.url.path == "/v1/inference/attestation-tickets":
            return httpx.Response(200, json={"ticket": "att-ticket", "expires_in": 30})
        return httpx.Response(404, json={"error": {"type": "not_found"}})

    client = ConfidentialClient(
        base_url=ORIGIN,
        api_key=api_key,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return client, paths, headers_seen


# ---- origin validation -------------------------------------------------------


def test_accepts_a_bare_https_origin_and_tolerates_a_trailing_slash() -> None:
    assert ConfidentialClient("https://api.anonrouter.ai", "ar_k").origin == "https://api.anonrouter.ai"
    assert ConfidentialClient("https://api.anonrouter.ai/", "ar_k").origin == "https://api.anonrouter.ai"


def test_refuses_plaintext_http_against_a_remote_host() -> None:
    # Over plaintext the API key travels in the clear and the origin a quote binds
    # proves nothing about who answered, so an attested route would be decorative.
    with pytest.raises(ConfidentialError, match="must be https"):
        ConfidentialClient("http://api.anonrouter.ai", "ar_k")
    with pytest.raises(ConfidentialError, match="loopback"):
        ConfidentialClient("http://api.anonrouter.ai", "ar_k", allow_insecure_http=True)


def test_permits_loopback_http_only_with_an_explicit_opt_in() -> None:
    with pytest.raises(ConfidentialError, match="must be https"):
        ConfidentialClient("http://localhost:8080", "ar_k")
    assert (
        ConfidentialClient("http://localhost:8080", "ar_k", allow_insecure_http=True).origin
        == "http://localhost:8080"
    )


def test_refuses_a_base_url_carrying_a_path_or_credentials() -> None:
    with pytest.raises(ConfidentialError, match="no path"):
        ConfidentialClient("https://api.anonrouter.ai/v1", "ar_k")
    with pytest.raises(ConfidentialError, match="bare origin"):
        ConfidentialClient("https://api.anonrouter.ai?x=1", "ar_k")
    with pytest.raises(ConfidentialError, match="bare origin"):
        ConfidentialClient("https://u:p@api.anonrouter.ai", "ar_k")


# ---- verify_gateway (hop 1) --------------------------------------------------


def test_verifies_the_plane_against_a_caller_supplied_policy() -> None:
    client, _, _ = make_client()
    result = client.verify_gateway(policy=gateway_test_policy())
    assert result["verdict"].reason is None
    assert result["verdict"].status == "ok"
    assert result["verdict"].verification_level == "provider-attested"
    assert result["origin"] == ORIGIN
    assert result["policy"]["origin"] == "caller-supplied"
    assert result["verdict"].binding is not None
    assert result["verdict"].binding.origin == ORIGIN


def test_binds_a_client_generated_nonce_not_a_server_chosen_one() -> None:
    client, paths, _ = make_client()
    first = client.verify_gateway(policy=gateway_test_policy())
    second = client.verify_gateway(policy=gateway_test_policy())
    assert first["verdict"].binding is not None
    assert second["verdict"].binding is not None
    assert first["verdict"].binding.nonce != second["verdict"].binding.nonce
    assert paths.count("/v1/gateway/attestation") == 2


def test_fails_closed_when_no_policy_is_pinned_for_the_origin() -> None:
    client, _, _ = make_client()
    # No caller policy and nothing shipped for this test origin: there is nothing to
    # check the evidence against, so reporting what it says would be reading the
    # server's own claim back to the caller.
    with pytest.raises(ConfidentialError, match="no pinned gateway policy"):
        client.verify_gateway()


def test_fails_closed_when_the_deployment_does_not_expose_attestation() -> None:
    client, _, _ = make_client("unavailable")
    with pytest.raises(ConfidentialError, match="does not expose gateway attestation"):
        client.verify_gateway(policy=gateway_test_policy())


def test_reports_a_failed_verdict_for_an_unreviewed_release() -> None:
    client, _, _ = make_client("wrong-release")
    result = client.verify_gateway(policy=gateway_test_policy())
    assert result["verdict"].status == "failed"
    assert result["verdict"].reason == "release_pinned"


def test_refuses_a_nonce_that_is_not_exactly_32_bytes() -> None:
    client, _, _ = make_client()
    with pytest.raises(ConfidentialError, match="exactly 64 hex characters"):
        client.verify_gateway(nonce="ab" * 8, policy=gateway_test_policy())


def test_never_sends_the_api_key_to_the_credential_free_route() -> None:
    client, _, headers_seen = make_client(api_key="ar_secret_key")
    client.verify_gateway(policy=gateway_test_policy())
    assert len(headers_seen) == 1
    assert "ar_secret_key" not in json.dumps(headers_seen[0])
    assert "authorization" not in headers_seen[0]


# ---- chat gating -------------------------------------------------------------


def test_chat_sends_nothing_when_the_plane_does_not_verify() -> None:
    client, paths, _ = make_client("wrong-release")
    with pytest.raises(ConfidentialError, match="did not verify"):
        client.chat(
            model="venice-uncensored",
            provider="venice",
            messages=[{"role": "user", "content": "canary-do-not-leak"}],
            max_output_tokens=32,
            require_gateway={"policy": gateway_test_policy()},
        )
    # The gate runs BEFORE the first authenticated call, so no ticket was spent and
    # no model was ever named to the gateway.
    assert paths == ["/v1/gateway/attestation"]


def test_chat_sends_nothing_when_the_plane_cannot_attest_itself() -> None:
    client, paths, _ = make_client("unavailable")
    with pytest.raises(ConfidentialError, match="did not verify"):
        client.chat(
            model="venice-uncensored",
            provider="venice",
            messages=[{"role": "user", "content": "canary-do-not-leak"}],
            max_output_tokens=32,
            require_gateway={"policy": gateway_test_policy()},
        )
    assert paths == ["/v1/gateway/attestation"]


def test_chat_without_a_gateway_requirement_does_not_call_hop_one() -> None:
    client, paths, _ = make_client()
    # Reaches the provider hop and fails there (the stub serves no attestation),
    # which is enough to prove hop 1 was never consulted.
    with pytest.raises(ConfidentialError):
        client.chat(
            model="venice-uncensored",
            provider="venice",
            messages=[{"role": "user", "content": "hello"}],
            max_output_tokens=32,
        )
    assert "/v1/gateway/attestation" not in paths


# ---- verify (both hops) ------------------------------------------------------


def test_gateway_hop_reports_unpinned_rather_than_passing() -> None:
    client, _, _ = make_client()
    hop = client._gateway_hop({})
    assert hop["requested"] is True
    assert hop["status"] == "unpinned"
    assert hop["verification_level"] is None


def test_gateway_hop_reports_unavailable_distinctly_from_failed() -> None:
    client, _, _ = make_client("unavailable")
    hop = client._gateway_hop({"policy": gateway_test_policy()})
    assert hop["status"] == "unavailable"

    failing, _, _ = make_client("wrong-release")
    assert failing._gateway_hop({"policy": gateway_test_policy()})["status"] == "failed"


def test_gateway_hop_reports_ok_with_policy_provenance() -> None:
    client, _, _ = make_client()
    hop = client._gateway_hop({"policy": gateway_test_policy()})
    assert hop["status"] == "ok"
    assert hop["verification_level"] == "provider-attested"
    assert hop["policy"]["origin"] == "caller-supplied"
