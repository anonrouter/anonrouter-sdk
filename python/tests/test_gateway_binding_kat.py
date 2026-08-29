"""Known-answer tests for the gateway attestation binding.

These read the SAME ``shared/vectors/gateway-binding.json`` the JS package loads.
The binding's canonical JSON is what the in-TEE producer hashes into the TDX
quote's report_data, so if Python and JS disagree about that serialization by a
single byte, one of them rejects every genuine quote and the other could accept a
digest computed over data it never inspected. These vectors are the contract that
makes shipping that impossible.
"""

from __future__ import annotations

from typing import Any

import pytest

from anonrouter_confidential.gateway.binding import (
    GATEWAY_BINDING_VERSION,
    GatewayBindingError,
    canonical_gateway_binding_json,
    gateway_binding_hash,
    normalize_gateway_binding,
)


def test_vectors_cover_this_binding_version(gateway_binding_vectors: dict[str, Any]) -> None:
    assert gateway_binding_vectors["bindingVersion"] == GATEWAY_BINDING_VERSION
    assert gateway_binding_vectors["digestAlgorithm"] == "sha512"
    assert len(gateway_binding_vectors["accepted"]) > 0
    assert len(gateway_binding_vectors["rejected"]) > 0


def test_accepted_vectors_reproduce_json_and_digest(
    gateway_binding_vectors: dict[str, Any],
) -> None:
    for vector in gateway_binding_vectors["accepted"]:
        assert canonical_gateway_binding_json(vector["binding"]) == vector["canonicalJson"], (
            f"canonical JSON drift: {vector['name']}"
        )
        assert gateway_binding_hash(vector["binding"]) == vector["bindingHash"], (
            f"digest drift: {vector['name']}"
        )
        # 64 bytes: exactly what fits in a TDX quote's report_data field.
        assert len(vector["bindingHash"]) == 128


def test_rejected_vectors_are_refused_on_the_named_field(
    gateway_binding_vectors: dict[str, Any],
) -> None:
    for vector in gateway_binding_vectors["rejected"]:
        with pytest.raises(GatewayBindingError) as excinfo:
            normalize_gateway_binding(vector["binding"])
        assert excinfo.value.field == vector["field"], f"wrong field for: {vector['name']}"


def test_case_and_prefix_normalize_before_hashing(
    gateway_binding_vectors: dict[str, Any],
) -> None:
    # Two spellings of the same identity must hash identically, or a client and a
    # TD that formatted the same value differently would never agree.
    lower = dict(gateway_binding_vectors["accepted"][0]["binding"])
    shouted = dict(lower)
    shouted["nonce"] = str(lower["nonce"]).upper()
    shouted["app_id"] = "0x" + str(lower["app_id"]).upper()
    shouted["compose_hash"] = "0x" + str(lower["compose_hash"]).upper()
    assert gateway_binding_hash(shouted) == gateway_binding_hash(lower)
