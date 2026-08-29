"""anonrouter-confidential: independently verify AnonRouter TEE/E2EE routes and run
confidential inference from Python.

Mirrors the JS ``@anonrouter/confidential`` surface and passes the SAME shared KAT
vectors, so Python and JS agree bit-for-bit. Verification fails closed and NEVER
emits ``hardware-verified``: the ceiling is ``provider-attested`` for NEAR/Venice/
Chutes and ``sdk-verified`` for Tinfoil via its official SDK.
"""

from __future__ import annotations

from . import crypto, gateway
from .client import ConfidentialClient, ConfidentialError, create_client
from .gateway import (
    GatewayAttestationBinding,
    GatewayBindingError,
    GatewayMeasurementPolicy,
    GatewayPolicyError,
    GatewayVerificationResult,
    TdxChainVerifier,
    canonical_gateway_binding_json,
    gateway_binding_hash,
    load_gateway_policy,
    normalize_gateway_binding,
    pinned_gateway_policy_for,
    verify_gateway_attestation,
)
from .measurements import (
    load_measurements,
    pinned_endpoint_identity_for,
    pinned_measurement_policy_for,
    tdx_tee_type,
)
from .tdx import (
    TDX_TEE_TYPE,
    ParsedTdxQuote,
    match_measurement_allowlist,
    parse_tdx_quote,
)
from .verify import (
    AttestationCheck,
    AttestationExpectations,
    NormalizedVerdict,
    verify_raw_evidence,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # client
    "create_client",
    "ConfidentialClient",
    "ConfidentialError",
    # verification: hop 2, the downstream provider route
    "verify_raw_evidence",
    "NormalizedVerdict",
    "AttestationCheck",
    "AttestationExpectations",
    # verification: hop 1, AnonRouter's own confidential routing plane
    "gateway",
    "verify_gateway_attestation",
    "GatewayVerificationResult",
    "GatewayAttestationBinding",
    "GatewayBindingError",
    "normalize_gateway_binding",
    "canonical_gateway_binding_json",
    "gateway_binding_hash",
    "GatewayMeasurementPolicy",
    "GatewayPolicyError",
    "load_gateway_policy",
    "pinned_gateway_policy_for",
    "TdxChainVerifier",
    # tdx
    "parse_tdx_quote",
    "ParsedTdxQuote",
    "match_measurement_allowlist",
    "TDX_TEE_TYPE",
    # pins
    "load_measurements",
    "pinned_measurement_policy_for",
    "pinned_endpoint_identity_for",
    "tdx_tee_type",
    # provider crypto (crypto.near / crypto.venice / crypto.chutes)
    "crypto",
]
