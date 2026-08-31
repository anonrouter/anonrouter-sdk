"""anonrouter_confidential.gateway.dcap: the official hardware-verification path.

Import this to reach ``hardware_verified``. It drives AnonRouter's reviewed offline
DCAP engine over a process boundary and acquires the Intel-signed collateral that
engine needs.

    from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

    verdict = client.verify_route(
        model=..., provider=...,
        gateway={"chain_verifier": create_anonrouter_dcap_verifier()},
    )

The package bundles no engine, by design. ``describe_dcap_installation()`` reports
whether one is present and, if not, exactly what to install and where this module
will look.
"""

from __future__ import annotations

from .collateral import (
    INTEL_CERT_BASE,
    INTEL_PCS_BASE,
    AcquiredCollateral,
    CollateralCache,
    CollateralError,
    DcapCollateral,
    extract_fmspc,
    extract_pck_chain,
    fetch_intel_collateral,
    normalize_quote_hex,
    read_next_update_ms,
    read_signed_document_signature,
    slice_signed_document,
)
from .engine import (
    DCAP_ENGINE_ENV,
    DCAP_ENGINE_PROGRAM,
    DCAP_ENGINE_REQUEST_VERSION,
    AnonRouterDcapVerifier,
    DcapEngineVerdictV1,
    DcapInstallationReport,
    PreparedDcapVerifier,
    ResolvedDcapBinary,
    build_dcap_engine_request,
    create_anonrouter_dcap_verifier,
    dcap_platform_target,
    describe_dcap_installation,
    engine_report_disagreement,
    file_sha256,
    parse_dcap_engine_verdict,
    resolve_dcap_verifier_binary,
    run_dcap_engine,
)

__all__ = [
    # The adapter
    "AnonRouterDcapVerifier",
    "create_anonrouter_dcap_verifier",
    "PreparedDcapVerifier",
    # Locating and identifying the engine
    "resolve_dcap_verifier_binary",
    "describe_dcap_installation",
    "dcap_platform_target",
    "file_sha256",
    "ResolvedDcapBinary",
    "DcapInstallationReport",
    "DCAP_ENGINE_PROGRAM",
    "DCAP_ENGINE_ENV",
    "DCAP_ENGINE_REQUEST_VERSION",
    # The wire contract, exported so it can be pinned by known-answer vectors
    "build_dcap_engine_request",
    "parse_dcap_engine_verdict",
    "run_dcap_engine",
    "engine_report_disagreement",
    "DcapEngineVerdictV1",
    # Collateral
    "fetch_intel_collateral",
    "CollateralCache",
    "CollateralError",
    "DcapCollateral",
    "AcquiredCollateral",
    "extract_pck_chain",
    "extract_fmspc",
    "slice_signed_document",
    "read_signed_document_signature",
    "read_next_update_ms",
    "normalize_quote_hex",
    "INTEL_PCS_BASE",
    "INTEL_CERT_BASE",
]
