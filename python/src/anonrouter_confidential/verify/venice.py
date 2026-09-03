"""Venice TEE/E2EE verifier.

Venice returns an Intel TDX quote, NVIDIA evidence, a nonce, and a secp256k1
signing/encryption key. We validate the structural quote bindings locally. Full
Intel/NVIDIA vendor-root verification is deliberately NOT inferred from Venice's
own ``verified`` booleans, so the honest maximum stays ``provider-attested``.

Verdict-for-verdict equivalent to the Venice verifier in ``@anonrouter/confidential``.
"""

from __future__ import annotations

import re
from typing import Any

from .._util import as_dict, as_str
from ..crypto.venice import eth_address_from_pub
from ..tdx import TDX_TEE_TYPE, parse_tdx_quote
from .checks import assemble_result, check, freshness_check, hex_equal, read_envelope
from .types import AttestationExpectations, NormalizedVerdict

VERIFIER_VERSION = "venice-tdx-receipt/2"
_VENICE_KEYSET_ALGO = "secp256k1-aes-256-gcm-hkdf-sha256"
_ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")


def _str_or_none(value: Any) -> str | None:
    return as_str(value)


def _derived_address(signing_public_key: str | None) -> str | None:
    if not signing_public_key:
        return None
    try:
        return eth_address_from_pub(signing_public_key)
    except ValueError:
        return None


def verify_venice(evidence: Any, expectations: AttestationExpectations) -> NormalizedVerdict:
    envelope = read_envelope(evidence, expectations)
    payload = as_dict(envelope.payload)
    checks = []

    quote_raw = _str_or_none(payload.get("intel_quote"))
    parsed = parse_tdx_quote(quote_raw) if quote_raw else None
    nonce = _str_or_none(payload.get("nonce"))
    model = _str_or_none(payload.get("model"))
    signing_address_raw = _str_or_none(payload.get("signing_address"))
    signing_address = signing_address_raw.lower() if signing_address_raw else None
    signing_public_key = _str_or_none(payload.get("signing_public_key")) or _str_or_none(payload.get("signing_key"))
    derived_address = _derived_address(signing_public_key)

    checks.append(check("evidence_present", bool(payload and quote_raw), True, None if quote_raw else "no Intel quote"))
    checks.append(check("quote_parsed", parsed is not None, True, None if parsed else "TDX quote did not parse"))
    checks.append(check(
        "expected_tee_type",
        parsed is not None and parsed.tee_type == TDX_TEE_TYPE,
        True,
        None if (parsed and parsed.tee_type == TDX_TEE_TYPE) else "not an Intel TDX quote",
    ))
    checks.append(check(
        "debug_disabled",
        parsed is not None and not parsed.debug_enabled,
        True,
        "TD debug mode enabled" if (parsed and parsed.debug_enabled) else None,
    ))
    checks.append(check(
        "nonce_binding",
        bool(parsed and nonce and hex_equal(nonce, expectations.nonce)
             and hex_equal(parsed.report_data[64:128], expectations.nonce)),
        True,
        None if nonce else "attestation did not carry the caller nonce",
    ))
    checks.append(check(
        "model_binding",
        model == expectations.upstream_model,
        True,
        None if model else "attestation did not name the route model",
    ))
    checks.append(check(
        "signing_algorithm",
        payload.get("signing_algo") == "ecdsa",
        True,
        None if payload.get("signing_algo") == "ecdsa" else "unsupported attested signing algorithm",
    ))
    checks.append(check(
        "signing_key_address",
        bool(derived_address and signing_address and hex_equal(derived_address, signing_address)),
        True,
        None if derived_address else "attested secp256k1 key was missing or malformed",
    ))

    address_report_prefix = (
        signing_address[2:].ljust(64, "0")
        if signing_address and _ADDR_RE.match(signing_address)
        else None
    )
    checks.append(check(
        "signing_address_quote_binding",
        bool(parsed and address_report_prefix and hex_equal(parsed.report_data[0:64], address_report_prefix)),
        True,
        None if address_report_prefix else "attested signing address was malformed",
    ))

    # ABSENT IS NOT THE SAME AS WRONG, and the difference decides what anyone
    # does next. "Did not match" says the provider asserted two contradictory
    # things -- an inconsistency to report to them. "Carried nothing" says the
    # provider asserted nothing at all -- a route to withhold until it does.
    # Three live Venice routes take the second path today and were being
    # reported as the first, which sends a reader hunting for a mismatch that
    # does not exist.
    #
    # The VERDICT is identical either way: a binding nobody stated is a binding
    # that did not hold. Only the reason changes.
    attestation = as_dict(payload.get("attestation"))
    nested_document_present = len(attestation) > 0
    reported_report_data = _str_or_none(attestation.get("report_data"))
    evidence_block = as_dict(attestation.get("evidence"))
    evidence_report_data = _str_or_none(evidence_block.get("quote_report_data"))
    reported_quote_bound = bool(
        parsed
        and hex_equal(reported_report_data, parsed.report_data)
        and hex_equal(evidence_report_data, parsed.report_data)
    )
    checks.append(check(
        "reported_quote_binding",
        reported_quote_bound,
        True,
        None
        if reported_quote_bound
        else "the evidence carried no nested attestation document, so nothing restates the quote's report_data"
        if not nested_document_present
        else "the nested attestation document omits report_data"
        if reported_report_data is None or evidence_report_data is None
        else "nested attestation report_data did not match the quote",
    ))

    keyset = as_dict(attestation.get("workload_keyset"))
    keyset_keys = keyset.get("e2ee_public_keys")
    key_in_workload = isinstance(keyset_keys, list) and any(
        isinstance(entry, dict)
        and entry.get("algo") == _VENICE_KEYSET_ALGO
        and isinstance(entry.get("public_key"), str)
        and signing_public_key is not None
        and hex_equal(entry["public_key"], signing_public_key)
        for entry in keyset_keys
    )
    checks.append(check(
        "workload_keyset_binding",
        key_in_workload,
        True,
        None
        if key_in_workload
        else "the evidence attests no workload keyset, so nothing binds the signing key to the workload that ran"
        if not isinstance(keyset_keys, list)
        else "the attested workload keyset does not contain the signing key",
    ))

    gpu = payload.get("nvidia_payload")
    gpu_present = isinstance(gpu, str) and len(gpu) > 0
    checks.append(check("gpu_evidence_present", gpu_present, True, None if gpu_present else "no NVIDIA GPU evidence"))
    checks.append(freshness_check(envelope.fetched_at_ms, expectations))

    measurements = (
        {
            "mrtd": parsed.mr_td,
            "mr_config_id": parsed.mr_config_id,
            "rtmr0": parsed.rtmr0,
            "rtmr1": parsed.rtmr1,
            "rtmr2": parsed.rtmr2,
            "rtmr3": parsed.rtmr3,
        }
        if parsed
        else {}
    )
    bound_nonce = expectations.nonce if (parsed and nonce and hex_equal(nonce, expectations.nonce)) else nonce
    return assemble_result(
        expectations=expectations,
        hardware_type="intel-tdx+nvidia-cc",
        requested_level="provider-attested",
        measurement_identities=measurements,
        model_weight_identity=None,
        attested_tls_spki=None,
        attested_encryption_key=signing_public_key,
        attested_signing_key=signing_address,
        bound_nonce=bound_nonce,
        verifier_version=VERIFIER_VERSION,
        supports_client_opaque_e2ee=True,
        checks=checks,
    )
