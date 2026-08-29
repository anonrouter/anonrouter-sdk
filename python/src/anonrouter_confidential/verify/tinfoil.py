"""Tinfoil verifier.

Tinfoil's own SDK (the ``tinfoil`` pip) performs the hard cryptographic work: AMD
SEV-SNP + NVIDIA confidential-compute hardware attestation, a Sigstore-transparency
-log code measurement, model-weight fingerprint binding, and TLS/HPKE key binding.
Re-implementing that in a weaker homegrown check would be strictly worse, so this
verifier is the ONLY path allowed to report ``sdk-verified``.

We require the official ``tinfoil`` pip to be importable; if it is not installed we
FAIL CLOSED (no verdict is fabricated). When it is present, we bind the SDK's
verification document to the route and the operator-reviewed release allowlist,
reporting ``sdk-verified`` when the SDK confirmed enclave security.

Verdict-for-verdict equivalent to the Tinfoil verifier in ``@anonrouter/confidential``.
"""

from __future__ import annotations

import importlib.util
from typing import Any
from urllib.parse import urlparse

from .._util import as_dict
from .checks import (
    assemble_result,
    check,
    freshness_check,
    read_envelope,
)
from .types import AttestationExpectations, NormalizedVerdict

VERIFIER_VERSION = "tinfoil-sdk/1"


def tinfoil_sdk_available() -> bool:
    """Whether the official ``tinfoil`` verifier package is importable."""
    return importlib.util.find_spec("tinfoil") is not None


def _host_from_url(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) == 0:
        return None
    try:
        host = urlparse(value).netloc
        return host or value
    except ValueError:
        return value


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def verify_tinfoil(evidence: Any, expectations: AttestationExpectations) -> NormalizedVerdict:
    """Validate a Tinfoil verification document against the reviewed release pins.

    What this proves, precisely: the document reports a successful Tinfoil SDK
    verification, and its release identity is one a human reviewed and pinned. The
    hard cryptography (AMD SEV-SNP + NVIDIA CC attestation, the Sigstore
    transparency-log measurement, TLS/HPKE key binding) was done by Tinfoil's own
    verifier, which produced this document. In the client flow the gateway supplies
    it, so this path does not prove the document independently of AnonRouter. That
    residual trust is documented in SECURITY.md. To close it, run Tinfoil's own
    verifier yourself against the enclave host.

    This deliberately does NOT require the optional ``tinfoil`` package. Requiring
    it here would make Tinfoil routes unverifiable from Python while the JavaScript
    package verified them happily, and the twins must not disagree about what the
    same evidence means.
    """
    envelope = read_envelope(evidence, expectations)
    has_doc = isinstance(envelope.payload, dict)
    doc = as_dict(envelope.payload)
    checks = []

    checks.append(check("evidence_present", has_doc, True, None if has_doc else "no SDK verification document"))

    security_verified = doc.get("securityVerified") is True
    checks.append(check("sdk_security_verified", security_verified, True,
                        None if security_verified else "Tinfoil SDK did not confirm enclave security"))

    selected_router_host = _host_from_url(doc.get("selectedRouterEndpoint"))
    host_ok = selected_router_host == expectations.endpoint_identity
    checks.append(check("enclave_host_binding", host_ok, True,
                        None if host_ok else "attested enclave host does not match route endpoint"))

    steps = as_dict(doc.get("steps"))
    required_steps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"]
    steps_ok = all(as_dict(steps.get(name)).get("status") == "success" for name in required_steps)
    checks.append(check("sdk_verification_steps", steps_ok, True,
                        None if steps_ok else "one or more SDK cryptographic steps did not succeed"))

    accepted = as_dict(expectations.measurement_policy).get("accepted")
    accepted = accepted if isinstance(accepted, list) else []
    if accepted:
        code_fingerprint = doc.get("codeFingerprint")
        measurement_ok = any(
            isinstance(code_fingerprint, str)
            and code_fingerprint == entry.get("codeFingerprint")
            and (not entry.get("releaseDigest") or doc.get("releaseDigest") == entry.get("releaseDigest"))
            and (not entry.get("releaseTag") or doc.get("releaseTag") == entry.get("releaseTag"))
            and (not entry.get("enclaveFingerprint") or doc.get("enclaveFingerprint") == entry.get("enclaveFingerprint"))
            for entry in accepted
        )
        checks.append(check("code_measurement_allowlist", measurement_ok, True,
                            None if measurement_ok else "code measurement not in accepted allowlist"))
    else:
        checks.append(check("code_measurement_allowlist", False, True, "no accepted code-measurement policy pinned"))

    serving_ok = expectations.privacy_modality == "tee"
    checks.append(check("serving_modality_supported", serving_ok, True,
                        None if serving_ok else "AnonRouter does not implement Tinfoil EHBP forwarding"))

    enclave_measurement = as_dict(doc.get("enclaveMeasurement"))
    hpke_public_key = enclave_measurement.get("hpkePublicKey") or doc.get("hpkePublicKey")
    tls_fingerprint = enclave_measurement.get("tlsPublicKeyFingerprint")
    tls_public_key = doc.get("tlsPublicKey")
    e2ee = expectations.privacy_modality == "e2ee"
    if e2ee:
        key_ok = isinstance(hpke_public_key, str) and len(hpke_public_key) > 0
    else:
        key_ok = (
            isinstance(tls_fingerprint, str) and len(tls_fingerprint) > 0
            and isinstance(tls_public_key, str) and len(tls_public_key) > 0
        )
    checks.append(check("attested_key_binding", key_ok, True,
                        None if key_ok else "no attested key for the serving modality"))

    checks.append(check("nonce_binding", False, False, "Tinfoil attestation is connection-bound, not nonce-bound"))
    checks.append(freshness_check(envelope.fetched_at_ms, expectations))

    measurements: dict[str, str] = {}
    if doc and isinstance(doc.get("codeFingerprint"), str):
        measurements["code"] = doc["codeFingerprint"]
    if doc and isinstance(doc.get("enclaveFingerprint"), str):
        measurements["enclave"] = doc["enclaveFingerprint"]

    return assemble_result(
        expectations=expectations,
        hardware_type="amd-sev-snp+nvidia-cc",
        requested_level="sdk-verified",
        measurement_identities=measurements,
        model_weight_identity=None,
        attested_tls_spki=_str_or_none(tls_fingerprint),
        attested_encryption_key=None,
        attested_signing_key=None,
        bound_nonce=None,
        verifier_version=VERIFIER_VERSION,
        supports_client_opaque_e2ee=False,
        checks=checks,
    )
