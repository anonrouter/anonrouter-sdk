"""Chutes TEE evidence verifier.

Validates every instance returned by the provider and the protocol-level bindings
Chutes documents: Intel TDX + debug-off, reviewed measurement identity, the
nonce/ML-KEM-key binding report_data[0:32] == sha256(nonce || pubkey), and the
per-instance certificate possession (RSA signature over the attested body, SPKI
hash bound in report_data[32:64]). Full Intel DCAP + NVIDIA NRAS chain verification
remains a separate fail-closed port, so the honest level is ``provider-attested``.

Verdict-for-verdict equivalent to the Chutes verifier in ``@anonrouter/confidential``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_der_x509_certificate

from .._util import as_dict, as_list
from ..tdx import TDX_TEE_TYPE, match_measurement_allowlist, parse_tdx_quote
from .checks import assemble_result, check, freshness_check, hex_equal, read_envelope
from .types import AttestationExpectations, NormalizedVerdict

VERIFIER_VERSION = "chutes-tdx/2"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_base64(value: Any) -> bytes | None:
    if not isinstance(value, str) or len(value) == 0:
        return None
    try:
        decoded = base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) > 0 else None


def _parse_json(value: Any) -> Any:
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _json_equal(a: Any, b: Any) -> bool:
    try:
        return json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)
    except (TypeError, ValueError):
        return False


def verify_chutes(evidence: Any, expectations: AttestationExpectations) -> NormalizedVerdict:
    envelope = read_envelope(evidence, expectations)
    payload = as_dict(envelope.payload)
    instances = as_list(payload.get("evidence"))
    failed_ids = as_list(payload.get("failed_instance_ids"))
    pubkeys = as_dict(payload.get("e2e_pubkeys"))
    checks = []

    checks.append(check("evidence_present", len(instances) > 0, True, None if instances else "no instance evidence"))
    checks.append(check("all_instances_returned", len(failed_ids) == 0, True,
                        None if not failed_ids else "evidence retrieval failed for one or more instances"))

    allowlist = as_list(as_dict(expectations.measurement_policy).get("accepted"))
    checks.append(check("measurement_policy_pinned", len(allowlist) > 0, True,
                        None if allowlist else "no accepted-measurement policy pinned"))

    first_measurements: dict[str, str] = {}
    first_bound_nonce: str | None = None
    every_encryption_key_bound = len(instances) > 0
    now_ms = expectations.now_ms if expectations.now_ms is not None else datetime.now(timezone.utc).timestamp() * 1000.0

    for index, raw_instance in enumerate(instances):
        instance = as_dict(raw_instance)
        label = f"instance_{index}"
        instance_id = instance.get("instance_id") if isinstance(instance.get("instance_id"), str) else None
        quote_raw = instance.get("quote") if isinstance(instance.get("quote"), str) else None
        parsed = parse_tdx_quote(quote_raw) if quote_raw else None
        checks.append(check(f"{label}_identity", bool(instance_id), True, None if instance_id else "instance id missing"))
        checks.append(check(f"{label}_quote_parsed", parsed is not None, True, None if parsed else "TDX quote did not parse"))
        if not parsed or not quote_raw:
            continue

        measurements = {
            "mrtd": parsed.mr_td,
            "rtmr0": parsed.rtmr0,
            "rtmr1": parsed.rtmr1,
            "rtmr2": parsed.rtmr2,
            "rtmr3": parsed.rtmr3,
        }
        if index == 0:
            first_measurements = measurements
        checks.append(check(f"{label}_expected_tee_type", parsed.tee_type == TDX_TEE_TYPE, True,
                            None if parsed.tee_type == TDX_TEE_TYPE else "not an Intel TDX quote"))
        checks.append(check(f"{label}_debug_disabled", not parsed.debug_enabled, True,
                            "TD debug mode enabled" if parsed.debug_enabled else None))
        measurements_accepted = match_measurement_allowlist(parsed, allowlist) is not None
        checks.append(check(f"{label}_measurement_allowlist", measurements_accepted, True,
                            None if measurements_accepted else "measurements not in accepted allowlist"))

        e2e_pubkey = pubkeys.get(instance_id) if instance_id and isinstance(pubkeys.get(instance_id), str) else None
        expected_nonce_key = _sha256_hex((expectations.nonce + e2e_pubkey).encode("utf-8")) if e2e_pubkey else None
        report_nonce_key = parsed.report_data[0:64]
        checks.append(check(f"{label}_nonce_key_binding", hex_equal(report_nonce_key, expected_nonce_key), True,
                            None if e2e_pubkey else "no discovered ML-KEM public key for instance"))
        every_encryption_key_bound = every_encryption_key_bound and hex_equal(report_nonce_key, expected_nonce_key)
        if index == 0 and expected_nonce_key and hex_equal(report_nonce_key, expected_nonce_key):
            first_bound_nonce = expectations.nonce

        certificate = _decode_base64(instance.get("certificate"))
        attested_body = _decode_base64(instance.get("attested_body"))
        signature = _decode_base64(instance.get("signature"))
        certificate_spki_hash: str | None = None
        possession_verified = False
        certificate_fresh = False
        if certificate and attested_body and signature:
            try:
                cert = load_der_x509_certificate(certificate)
                cert_public_key: Any = cert.public_key()
                spki = cert_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                certificate_spki_hash = _sha256_hex(spki)
                try:
                    # Chutes instance certs are RSA; verify possession of the key.
                    cert_public_key.verify(signature, attested_body, padding.PKCS1v15(), hashes.SHA256())
                    possession_verified = True
                except (InvalidSignature, TypeError, ValueError):
                    possession_verified = False
                at = now_ms / 1000.0
                certificate_fresh = cert.not_valid_before_utc.timestamp() <= at <= cert.not_valid_after_utc.timestamp()
            except (ValueError, TypeError):
                pass
        checks.append(check(f"{label}_certificate_spki_binding",
                            hex_equal(parsed.report_data[64:128], certificate_spki_hash), True,
                            None if certificate_spki_hash else "certificate could not be parsed"))
        checks.append(check(f"{label}_certificate_freshness", certificate_fresh, True,
                            None if certificate_fresh else "instance certificate is outside its validity window"))
        checks.append(check(f"{label}_key_possession", possession_verified, True,
                            None if possession_verified else "RSA signature over attested_body did not verify"))

        body = as_dict(_parse_json(attested_body.decode("utf-8", errors="replace")) if attested_body else None)
        gpu = as_list(instance.get("gpu_evidence"))
        body_evidence = as_dict(body.get("evidence"))
        inner_gpu = _parse_json(body_evidence.get("nvtrust_evidence"))
        checks.append(check(f"{label}_attested_nonce", bool(body) and body.get("nonce") == expectations.nonce, True,
                            None if (body and body.get("nonce") == expectations.nonce) else "signed body nonce mismatch"))
        checks.append(check(f"{label}_attested_quote", bool(body) and body_evidence.get("tdx_quote") == quote_raw, True,
                            None if (body and body_evidence.get("tdx_quote") == quote_raw) else "signed body quote mismatch"))
        gpu_evidence_signed = isinstance(inner_gpu, list) and _json_equal(inner_gpu, gpu)
        checks.append(check(f"{label}_attested_gpu_evidence", gpu_evidence_signed, True,
                            None if gpu_evidence_signed else "signed body GPU evidence mismatch"))
        gpu_shape_ok = len(gpu) > 0 and all(
            isinstance(item, dict) and isinstance(item.get("certificate"), str) and isinstance(item.get("evidence"), str)
            for item in gpu
        )
        checks.append(check(f"{label}_gpu_evidence_present", gpu_shape_ok, True,
                            None if gpu_shape_ok else "no complete NVIDIA GPU evidence"))

    # MODEL BINDING: STATED NOWHERE, so it is reported rather than omitted.
    #
    # Chutes' evidence names the instance, its measurements and its ML-KEM key,
    # but never the weights that were loaded. Venice's ``model_binding`` is a
    # REQUIRED check because Venice states a model and can therefore contradict
    # itself; there is nothing here to contradict.
    #
    # Leaving the check out entirely was the wrong answer, and it was the answer
    # this file gave. A verdict with no ``model_binding`` line reads as a route
    # where the question does not arise, when in fact it arises and the provider
    # does not answer it. It is advisory rather than required because the route
    # genuinely works and refusing it would be a policy decision about live
    # traffic, not a verification result — but a reader now sees the gap in
    # ``advisory_gaps`` instead of having to know the format to infer it.
    #
    # What still binds the model on this route is AnonRouter's own attested relay
    # echoing the route back, which the two-hop verdict cross-checks. That is a
    # weaker statement than the provider's enclave naming its own weights, and
    # the two must not be read as the same thing.
    checks.append(check(
        "model_binding", False, False,
        "provider evidence names no model; the route model rests on the gateway echo",
    ))

    checks.append(freshness_check(envelope.fetched_at_ms, expectations))

    attested_encryption_key = None
    if len(pubkeys) == 1:
        attested_encryption_key = str(next(iter(pubkeys.values())))

    return assemble_result(
        expectations=expectations,
        hardware_type="intel-tdx+nvidia-cc",
        # Ceiling is provider-attested: no vetted DCAP/NRAS chain verifier is wired.
        requested_level="provider-attested",
        measurement_identities=first_measurements,
        model_weight_identity=None,
        attested_tls_spki=None,
        attested_encryption_key=attested_encryption_key,
        attested_signing_key=None,
        bound_nonce=first_bound_nonce,
        verifier_version=VERIFIER_VERSION,
        supports_client_opaque_e2ee=expectations.privacy_modality == "e2ee" and every_encryption_key_bound,
        checks=checks,
    )
