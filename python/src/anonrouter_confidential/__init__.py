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
from .media import (
    DEFAULT_CONTROL_ORIGIN,
    DEFAULT_INFERENCE_ORIGIN,
    IMAGE_DEFAULT_SIZE,
    IMAGE_MAX_DIMENSION,
    IMAGE_MAX_PROMPT_CHARS,
    IMAGE_MIN_DIMENSION,
    IMAGE_RESPONSE_FORMAT,
    MEDIA_ERROR_CODES,
    SPEECH_MAX_INPUT_CHARS,
    SPEECH_MAX_VOICE_CHARS,
    SPEECH_RESPONSE_FORMAT,
    AudioApi,
    GeneratedImage,
    ImageGenerateResult,
    ImagesApi,
    MediaError,
    MediaErrorDiagnostics,
    MediaRateLimit,
    SpeechApi,
    SpeechCreateResult,
    canonical_image_size,
    redact_headers,
    utf16_length,
)
from .route_policy import (
    confidential_route_policy_version,
    is_route_withheld_by_service,
    offered_confidential_routes,
    withheld_confidential_routes,
    withheld_route_classification,
    withheld_route_message,
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
from .verify.route import (
    RequestedRoute,
    RouteBindingMismatch,
    RouteHopVerdict,
    RouteVerdict,
    assemble_route_verdict,
    gateway_hop_verdict,
    hop_not_requested,
    hop_unavailable,
    provider_hop_verdict,
)
from .verify.state import (
    TRUSTED_STATES,
    RouteVerificationState,
    at_least,
    describe_state,
    is_trusted,
    state_for_level,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # client
    "create_client",
    "ConfidentialClient",
    "ConfidentialError",
    # ticketed media (image / speech). `client.images.generate(...)` and
    # `client.audio.speech.create(...)` run the two-origin ticket exchange
    # automatically: the API key mints a content-free single-use ticket at the
    # control origin, and the prompt or text goes only to the confidential
    # inference origin, authenticated by that ticket alone. An official OpenAI
    # client cannot perform this exchange -- one base URL, one credential.
    "ImagesApi",
    "AudioApi",
    "SpeechApi",
    "ImageGenerateResult",
    "SpeechCreateResult",
    "GeneratedImage",
    "MediaError",
    "MediaErrorDiagnostics",
    "MediaRateLimit",
    "MEDIA_ERROR_CODES",
    "redact_headers",
    "utf16_length",
    "canonical_image_size",
    "DEFAULT_CONTROL_ORIGIN",
    "DEFAULT_INFERENCE_ORIGIN",
    "IMAGE_DEFAULT_SIZE",
    "IMAGE_MIN_DIMENSION",
    "IMAGE_MAX_DIMENSION",
    "IMAGE_MAX_PROMPT_CHARS",
    "IMAGE_RESPONSE_FORMAT",
    "SPEECH_MAX_INPUT_CHARS",
    "SPEECH_MAX_VOICE_CHARS",
    "SPEECH_RESPONSE_FORMAT",
    # THE STABLE CONTRACT: ordered states + the two-hop route verdict
    "RouteVerificationState",
    "RouteVerdict",
    "RouteHopVerdict",
    "RouteBindingMismatch",
    "RequestedRoute",
    "assemble_route_verdict",
    "gateway_hop_verdict",
    "provider_hop_verdict",
    "hop_not_requested",
    "hop_unavailable",
    "at_least",
    "is_trusted",
    "describe_state",
    "state_for_level",
    "TRUSTED_STATES",
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
    "confidential_route_policy_version",
    "is_route_withheld_by_service",
    "offered_confidential_routes",
    "withheld_confidential_routes",
    "withheld_route_classification",
    "withheld_route_message",
    "pinned_measurement_policy_for",
    "pinned_endpoint_identity_for",
    "tdx_tee_type",
    # provider crypto (crypto.near / crypto.venice / crypto.chutes)
    "crypto",
]
