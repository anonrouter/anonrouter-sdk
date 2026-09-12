"""Route-binding negative controls, one per field the ticket binds.

Mirrors ``js/confidential/test/route-binding-negatives.test.ts`` case for case.

AnonRouter's attestation ticket is minted against exactly one catalog row and
binds five things: the provider, the requested (catalog) model, the upstream
(provider-native) model, the privacy class, and -- through the redemption -- a
single use with a short expiry. The client's fresh nonce binds the sixth.

A hop verifier can check NONE of that. It is handed one enclave's evidence and
asked whether that enclave is sound; a perfectly sound enclave is still the wrong
enclave if the caller asked for a different route. So each binding is checked
where both sides are visible, and each gets a test here that fails when the check
is removed.

These drive the real client through a stub gateway rather than calling
``assemble_route_verdict`` directly: a binding rule exercised only by hand-built
inputs cannot tell a wired-up check from a dead one, and two of the defects these
cover were invisible to ``test_route_contract.py`` for exactly that reason.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anonrouter_confidential.client import ConfidentialClient, ConfidentialError
from anonrouter_confidential.crypto.venice import eth_address_from_pub

ORIGIN = "https://confidential.test.invalid"
CONTROL = "https://control.test.invalid"
CATALOG_MODEL = "openai/gpt-oss-20b"
UPSTREAM_MODEL = "e2ee-gpt-oss-20b-p"

TINFOIL_FP = "6d" * 48


def _build_quote(report_data: bytes) -> str:
    buf = bytearray(632)
    buf[0:2] = (4).to_bytes(2, "little")
    buf[4:8] = (0x81).to_bytes(4, "little")
    buf[184:232] = bytes(range(48))
    buf[232:280] = b"\x01" + bytes(47)
    buf[376:424] = bytes([0xAA]) * 48
    buf[424:472] = bytes([0xBB]) * 48
    buf[472:520] = bytes([0xCC]) * 48
    buf[520:568] = bytes([0xDD]) * 48
    buf[568:632] = report_data
    return buf.hex()


def venice_evidence(nonce: str, upstream_model: str) -> dict[str, Any]:
    """A self-consistent Venice enclave document bound to the caller's nonce."""
    priv = ec.derive_private_key(
        0x9911AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556677, ec.SECP256K1()
    )
    pub_hex = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
    address = eth_address_from_pub(pub_hex)
    report_data = bytes.fromhex(address[2:]) + bytes(12) + bytes.fromhex(nonce)
    return {
        "intel_quote": _build_quote(report_data),
        "nvidia_payload": "nvidia-gpu-evidence-blob",
        "nonce": nonce,
        "model": upstream_model,
        "signing_algo": "ecdsa",
        "signing_public_key": pub_hex,
        "signing_address": address,
        "attestation": {
            "report_data": report_data.hex(),
            "evidence": {"quote_report_data": report_data.hex()},
            "workload_keyset": {
                "e2ee_public_keys": [
                    {"algo": "secp256k1-aes-256-gcm-hkdf-sha256", "public_key": pub_hex}
                ]
            },
        },
    }


def tinfoil_document() -> dict[str, Any]:
    """The document Tinfoil's official verifier produces for a signed release.

    Plus the transport binding AnonRouter's worker records after pinning the
    serving connection to the key in that verified report. The relay supplies
    both; the document alone cannot establish what key is actually being served.
    """
    tls_fingerprint = "19" * 32
    return {
        "schemaVersion": 1,
        "securityVerified": True,
        "enclaveHost": "inference.tinfoil.sh",
        "selectedRouterEndpoint": "inference.tinfoil.sh",
        "configRepo": "tinfoilsh/confidential-model-router",
        "releaseTag": "v99.0.0",
        "releaseDigest": "7d" * 32,
        "codeFingerprint": TINFOIL_FP,
        "enclaveFingerprint": TINFOIL_FP,
        "enclaveMeasurement": {"tlsPublicKeyFingerprint": tls_fingerprint},
        "tlsPublicKey": tls_fingerprint,
        "transportBinding": {
            "mode": "tls-pinned",
            "endpointIdentity": "inference.tinfoil.sh",
            "observedTlsSpki": tls_fingerprint,
            "verified": True,
        },
        "verifier": {"name": "@tinfoilsh/verifier", "version": "1.2.1"},
        "steps": {
            "fetchDigest": {"status": "success"},
            "verifyCode": {"status": "success"},
            "verifyEnclave": {"status": "success"},
            "compareMeasurements": {"status": "success"},
            "verifyCertificate": {"status": "success"},
        },
    }


_ABSENT = object()


def make_client(
    *,
    provider: Any = _ABSENT,
    model: Any = _ABSENT,
    upstream_model: str = UPSTREAM_MODEL,
    privacy_class: Any = _ABSENT,
    protocol: Any = _ABSENT,
    tee: bool = False,
    mint_error: tuple[int, str] | None = None,
) -> tuple[ConfidentialClient, list[dict[str, Any]]]:
    """A stub AnonRouter in the two-origin production shape.

    ``None`` for a field means ABSENT, which a client must treat differently from
    present-and-wrong.
    """
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "origin": f"{request.url.scheme}://{request.url.netloc.decode()}",
                "path": request.url.path,
                "authorization": request.headers.get("authorization"),
                "ticket": request.headers.get("x-anonrouter-ticket"),
            }
        )
        if request.url.path == "/v1/inference/attestation-tickets":
            if mint_error is not None:
                status, kind = mint_error
                return httpx.Response(status, json={"error": {"type": kind, "message": "refused"}})
            return httpx.Response(200, json={"ticket": "att-ticket", "expires_in": 60})
        if request.url.path == "/v1/tee/attestation":
            nonce = json.loads(request.content.decode())["nonce"]
            body: dict[str, Any] = {
                "evidence": tinfoil_document() if tee else venice_evidence(nonce, upstream_model),
                "provider": "tinfoil" if tee else "venice",
                "model": CATALOG_MODEL,
                "upstream_model": upstream_model,
                "privacy_class": "tee" if tee else "e2ee",
            }
            for key, value in (
                ("provider", provider),
                ("model", model),
                ("privacy_class", privacy_class),
                ("protocol", protocol),
            ):
                if value is _ABSENT:
                    continue
                if value is None:
                    body.pop(key, None)
                else:
                    body[key] = value
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": {"type": "not_found"}})

    client = ConfidentialClient(
        base_url=ORIGIN,
        control_base_url=CONTROL,
        api_key="ar_canary_key",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return client, seen


# ---- the requested-model binding ---------------------------------------------


def test_refuses_a_route_whose_attested_catalog_model_is_not_the_one_asked_for() -> None:
    # THE SUBSTITUTION THIS CATCHES. Both hops can be flawless and the enclave
    # genuinely sound, while the gateway quietly served a cheaper or less private
    # model than the caller named.
    client, _ = make_client(model="deepseek/deepseek-v4-flash", upstream_model="e2ee-deepseek-v4-flash")
    verdict = client.verify_route(CATALOG_MODEL, "venice")

    assert verdict.trusted is False
    assert verdict.overall_state == "untrusted"
    assert {
        "field": "requested_model",
        "expected": CATALOG_MODEL,
        "observed": "deepseek/deepseek-v4-flash",
        "source": "gateway",
    } in [m.as_dict() for m in verdict.binding_mismatches]


def test_accepts_the_route_it_was_asked_for() -> None:
    client, _ = make_client()
    verdict = client.verify_route(CATALOG_MODEL, "venice")
    assert verdict.binding_mismatches == []
    assert verdict.trusted is True


def test_does_not_invent_a_mismatch_against_a_gateway_too_old_to_echo_the_model() -> None:
    client, _ = make_client(model=None)
    verdict = client.verify_route(CATALOG_MODEL, "venice")
    assert verdict.binding_mismatches == []


# ---- the provider binding ----------------------------------------------------


def test_refuses_a_gateway_that_served_a_different_provider() -> None:
    client, _ = make_client(provider="chutes")
    verdict = client.verify_route(CATALOG_MODEL, "venice")
    assert verdict.trusted is False
    assert any(m.field_name == "provider" for m in verdict.binding_mismatches)


# ---- the privacy-modality binding --------------------------------------------


def test_modality_is_read_from_the_route_not_guessed_from_the_provider_name() -> None:
    # The modality is a per-row catalog fact. Venice publishes `private` and
    # `e2ee` rows today and could publish a `tee` row tomorrow with no code change
    # anywhere; Tinfoil is `tee` on every row it publishes today and could add an
    # E2EE one.
    client, _ = make_client(tee=True, provider="venice", privacy_class="tee")
    verdict = client.verify_route(CATALOG_MODEL, "venice")

    assert verdict.route.privacy_modality == "tee"
    assert verdict.route.privacy_modality_source == "gateway-attested"
    assert verdict.content_visible_to_anonrouter is True
    assert verdict.binding_mismatches == []


def test_refuses_a_route_served_under_a_different_class_than_pinned() -> None:
    client, _ = make_client(tee=True, provider="venice", privacy_class="tee")
    verdict = client.verify_route(CATALOG_MODEL, "venice", privacy_class="e2ee")

    assert verdict.trusted is False
    assert {
        "field": "privacy_modality",
        "expected": "e2ee",
        "observed": "tee",
        "source": "gateway",
    } in [m.as_dict() for m in verdict.binding_mismatches]


def test_never_claims_content_is_hidden_when_the_class_was_not_established() -> None:
    # `content_visible_to_anonrouter is False` is a positive claim that
    # AnonRouter's build is outside the caller's trust set. A gateway that said
    # nothing established no such thing, so the weaker claim is the honest one.
    client, _ = make_client(privacy_class=None)
    verdict = client.verify_route(CATALOG_MODEL, "venice")

    assert verdict.route.privacy_modality_source == "unestablished"
    assert verdict.content_visible_to_anonrouter is True


def test_lets_the_caller_pin_the_class_they_reviewed() -> None:
    client, _ = make_client(privacy_class=None)
    verdict = client.verify_route(CATALOG_MODEL, "venice", privacy_class="e2ee")
    assert verdict.route.privacy_modality_source == "caller-pinned"
    assert verdict.content_visible_to_anonrouter is False


# ---- a TEE route is verifiable, not an unsupported case ----------------------


def test_verifies_a_ticketed_tee_route_end_to_end() -> None:
    # The SDK used to tell callers a TEE-only route could not be verified against
    # this host, because AnonRouter's mint refused every non-E2EE route. The mint
    # now issues for any callable tee/e2ee route with a registered verifier.
    client, seen = make_client(tee=True, upstream_model="nomic-embed-text")
    verdict = client.verify_route("nomic-ai/nomic-embed-text", "tinfoil")

    assert verdict.provider.state != "unavailable"
    assert verdict.provider.failed_checks == []
    assert verdict.route.privacy_modality == "tee"
    to_content = [c for c in seen if c["origin"] == ORIGIN]
    assert all(c["authorization"] is None for c in to_content)
    assert next(c for c in seen if c["path"] == "/v1/tee/attestation")["ticket"] == "att-ticket"


def test_names_the_mints_own_refusal_rather_than_a_rule_about_tee_routes() -> None:
    client, _ = make_client(mint_error=(400, "model_not_e2ee"))
    verdict = client.verify_route("nomic-ai/nomic-embed-text", "tinfoil")
    assert verdict.trusted is False
    assert verdict.provider.reason is not None


# ---- credential isolation ----------------------------------------------------


def test_never_sends_the_api_key_to_the_confidential_origin() -> None:
    client, seen = make_client()
    client.verify_route(CATALOG_MODEL, "venice")

    to_content = [c for c in seen if c["origin"] == ORIGIN]
    assert to_content
    assert all(c["authorization"] is None for c in to_content)
    to_control = [c for c in seen if c["origin"] == CONTROL]
    assert all(c["authorization"] == "Bearer ar_canary_key" for c in to_control)


# ---- chat never encrypts to a route that cannot decrypt ----------------------


def test_chat_refuses_a_tee_route_before_spending_a_paid_ticket() -> None:
    client, seen = make_client(tee=True, provider="venice", privacy_class="tee")
    with pytest.raises(ConfidentialError, match="TEE route"):
        client.chat(CATALOG_MODEL, "venice", [{"role": "user", "content": "canary"}], 32)
    assert not any(c["path"] == "/v1/inference/tickets" for c in seen)


def test_chat_refuses_a_protocol_the_gateway_did_not_offer() -> None:
    client, seen = make_client(protocol="venice-hpke-v2")
    with pytest.raises(ConfidentialError, match="protocol"):
        client.chat(CATALOG_MODEL, "venice", [{"role": "user", "content": "canary"}], 32)
    assert not any(c["path"] == "/v1/inference/tickets" for c in seen)
