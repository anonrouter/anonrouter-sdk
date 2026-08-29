"""Hop 1: verify AnonRouter's OWN confidential routing plane.

The verifiers in ``anonrouter_confidential.verify`` answer "did the UPSTREAM model
provider run my request in an enclave?". This package answers the other half: "is
the AnonRouter data plane I am connected to the exact reviewed build, running
inside an Intel TDX confidential VM, bound to my nonce and my origin?".

Neither hop implies the other, which is why they are separate modules with
separate verdicts. Mirrors ``@anonrouter/confidential``'s ``src/gateway/*`` and
passes the same shared KAT vectors.
"""

from __future__ import annotations

from .app_compose import (
    AppComposeError,
    AttestedAppCompose,
    AttestedImageReference,
    extract_compose_images,
    read_attested_app_compose,
)
from .binding import (
    GATEWAY_BINDING_DIGEST_ALGORITHM,
    GATEWAY_BINDING_DIGEST_HEX_LENGTH,
    GATEWAY_BINDING_VERSION,
    GATEWAY_NONCE_BYTES,
    GATEWAY_NONCE_HEX_LENGTH,
    GatewayAttestationBinding,
    GatewayBindingError,
    assert_gateway_nonce,
    canonical_gateway_binding_json,
    canonical_gateway_origin,
    gateway_binding_digest,
    gateway_binding_hash,
    normalize_gateway_binding,
)
from .event_log import (
    RTMR_INITIAL_VALUE,
    DstackEventLogEntry,
    EventLogError,
    compute_rtmr3_event_digest_v1,
    inconsistent_rtmr3_events,
    parse_event_log,
    replay_register,
    replay_rtmrs,
    rtmr3_event_digest,
    rtmr3_event_digest_is_self_consistent,
    single_event_payload,
)
from .policy import (
    GatewayMeasurementPolicy,
    GatewayPlatformMeasurements,
    GatewayPolicyEntry,
    GatewayPolicyError,
    gateway_policy_registry,
    load_gateway_policy,
    pinned_gateway_policy_for,
)
from .verify import (
    GatewayVerificationResult,
    TdxChainVerifier,
    verify_gateway_attestation,
)

__all__ = [
    # binding
    "GatewayAttestationBinding",
    "GatewayBindingError",
    "normalize_gateway_binding",
    "canonical_gateway_binding_json",
    "canonical_gateway_origin",
    "gateway_binding_digest",
    "gateway_binding_hash",
    "assert_gateway_nonce",
    "GATEWAY_BINDING_VERSION",
    "GATEWAY_BINDING_DIGEST_ALGORITHM",
    "GATEWAY_BINDING_DIGEST_HEX_LENGTH",
    "GATEWAY_NONCE_BYTES",
    "GATEWAY_NONCE_HEX_LENGTH",
    # event log
    "DstackEventLogEntry",
    "EventLogError",
    "parse_event_log",
    "replay_rtmrs",
    "replay_register",
    "compute_rtmr3_event_digest_v1",
    "rtmr3_event_digest",
    "rtmr3_event_digest_is_self_consistent",
    "inconsistent_rtmr3_events",
    "single_event_payload",
    "RTMR_INITIAL_VALUE",
    # app compose
    "AttestedAppCompose",
    "AttestedImageReference",
    "AppComposeError",
    "read_attested_app_compose",
    "extract_compose_images",
    # policy
    "GatewayMeasurementPolicy",
    "GatewayPlatformMeasurements",
    "GatewayPolicyEntry",
    "GatewayPolicyError",
    "load_gateway_policy",
    "gateway_policy_registry",
    "pinned_gateway_policy_for",
    # verify
    "verify_gateway_attestation",
    "GatewayVerificationResult",
    "TdxChainVerifier",
]
