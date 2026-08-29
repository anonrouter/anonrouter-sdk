"""NEAR AI verifier.

NEAR runs inference in Intel-TDX Confidential VMs and, for a direct route, terminates
TLS INSIDE the enclave. We verify (all fail-closed): the caller nonce bound in
report_data[32:64]; the attested TLS SPKI bound in report_data[0:32] ==
sha256(signing_address || tls_cert_fingerprint); model_name equals the route model;
mr_config_id binds the pinned app_compose ("01" + sha256(app_compose)); the boot
measurements match NEAR's reviewed allowlist; TD debug disabled. The raw TDX/NRAS
chains are not verified here, so the honest level is ``provider-attested``.

Verdict-for-verdict equivalent to the NEAR verifier in ``@anonrouter/confidential``.
Covers attestation verification only; the per-request signature path is not part of
the client SDK surface.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .._util import as_dict, as_list, as_str
from ..tdx import TDX_TEE_TYPE, match_measurement_allowlist, parse_tdx_quote
from .checks import (
    assemble_result,
    check,
    freshness_check,
    hex_equal,
    nonce_binding_check,
    read_envelope,
)
from .types import AttestationExpectations, NormalizedVerdict

VERIFIER_VERSION = "near-tdx/1"
_ALL_ZERO_MR_CONFIG = "00" * 48


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _from_hex(value: str) -> bytes:
    clean = value.lower().removeprefix("0x")
    if len(clean) % 2 != 0:
        raise ValueError("invalid hex")
    return bytes.fromhex(clean)


def _str_or_none(value: Any) -> str | None:
    return as_str(value)


def verify_near(evidence: Any, expectations: AttestationExpectations) -> NormalizedVerdict:
    envelope = read_envelope(evidence, expectations)
    payload = as_dict(envelope.payload)
    checks = []

    quote_raw = _str_or_none(payload.get("intel_quote"))
    has_quote = bool(quote_raw)
    checks.append(check("evidence_present", has_quote, True, None if has_quote else "no intel_quote in report"))
    parsed = parse_tdx_quote(quote_raw) if has_quote else None
    checks.append(check("quote_parsed", parsed is not None, True, None if parsed else "TDX quote did not parse"))

    measurements: dict[str, str] = {}
    tls_fingerprint = _str_or_none(payload.get("tls_cert_fingerprint"))
    signing_address = _str_or_none(payload.get("signing_address"))
    model_name = _str_or_none(payload.get("model_name"))
    info = as_dict(payload.get("info"))
    tcb_info = as_dict(info.get("tcb_info"))
    app_compose_obj = as_dict(tcb_info.get("app_compose"))
    app_compose = _str_or_none(payload.get("app_compose")) or _str_or_none(app_compose_obj.get("docker_compose_file"))
    matched_policy = False

    if parsed:
        measurements = {
            "mrtd": parsed.mr_td,
            "rtmr0": parsed.rtmr0,
            "rtmr1": parsed.rtmr1,
            "rtmr2": parsed.rtmr2,
            "rtmr3": parsed.rtmr3,
            "mr_config_id": parsed.mr_config_id,
        }
        checks.append(check("expected_tee_type", parsed.tee_type == TDX_TEE_TYPE, True,
                            None if parsed.tee_type == TDX_TEE_TYPE else "not an Intel TDX quote"))
        checks.append(check("debug_disabled", not parsed.debug_enabled, True,
                            "TD debug mode enabled" if parsed.debug_enabled else None))

        report_first = parsed.report_data[0:64]
        report_second = parsed.report_data[64:128]
        checks.append(nonce_binding_check(expectations.nonce, report_second))

        if tls_fingerprint and signing_address:
            try:
                expected_first: str | None = _sha256_hex(_from_hex(signing_address) + _from_hex(tls_fingerprint))
            except ValueError:
                expected_first = None
            checks.append(check("tls_spki_binding", hex_equal(report_first, expected_first), True,
                                None if expected_first else "malformed signing_address/tls fingerprint"))
        else:
            checks.append(check("tls_spki_binding", False, True, "attestation did not bind a TLS SPKI"))

        compose_sha256 = _sha256_hex(app_compose.encode("utf-8")) if app_compose else None
        if compose_sha256 and parsed.mr_config_id != _ALL_ZERO_MR_CONFIG:
            expected_config = ("01" + compose_sha256).ljust(96, "0")
            reported_compose_hash = _str_or_none(payload.get("compose_hash"))
            checks.append(check("compose_binding", hex_equal(parsed.mr_config_id, expected_config), True, None))
            checks.append(check("reported_compose_hash", hex_equal(reported_compose_hash, compose_sha256), True,
                                None if reported_compose_hash else "report did not include compose hash"))
        elif parsed.mr_config_id == _ALL_ZERO_MR_CONFIG:
            checks.append(check("compose_binding", False, True, "mr_config_id is all-zero and does not bind the compose"))
        else:
            checks.append(check("compose_binding", False, True, "no app_compose provided to bind"))

        allowlist = as_list(as_dict(expectations.measurement_policy).get("accepted"))
        if allowlist:
            matched_name = match_measurement_allowlist(parsed, allowlist)
            matched_entry = next((e for e in allowlist if e.get("name") == matched_name), None) if matched_name else None
            entry_compose = as_str(matched_entry.get("composeSha256")) if matched_entry else None
            matched_policy = entry_compose is not None and hex_equal(entry_compose, compose_sha256)
            checks.append(check("measurement_allowlist", matched_policy, True,
                                None if matched_policy else "measurements not in accepted allowlist"))
        else:
            checks.append(check("measurement_allowlist", False, True, "no accepted-measurement policy pinned"))

    checks.append(check("model_binding", model_name == expectations.upstream_model, True,
                        None if model_name else "attestation did not name a model"))
    gpu = payload.get("nvidia_payload")
    gpu_ok = isinstance(gpu, str) and len(gpu) > 0
    checks.append(check("gpu_evidence_present", gpu_ok, True, None if gpu_ok else "no NVIDIA GPU evidence"))
    checks.append(freshness_check(envelope.fetched_at_ms, expectations))

    bound_nonce = parsed.report_data[64:128] if parsed else None
    return assemble_result(
        expectations=expectations,
        hardware_type="intel-tdx+nvidia-cc",
        # Ceiling is provider-attested: no vetted DCAP/NRAS chain verifier is wired.
        requested_level="provider-attested",
        measurement_identities=measurements,
        model_weight_identity=None,
        attested_tls_spki=tls_fingerprint,
        attested_encryption_key=_str_or_none(payload.get("signing_public_key")),
        attested_signing_key=signing_address,
        bound_nonce=expectations.nonce if (parsed and hex_equal(expectations.nonce, bound_nonce)) else bound_nonce,
        verifier_version=VERIFIER_VERSION,
        supports_client_opaque_e2ee=True,
        checks=checks,
    )
