"""Tinfoil verifier.

Tinfoil's own SDK (the ``tinfoil`` package) performs the hard cryptographic work:
AMD SEV-SNP + NVIDIA confidential-compute hardware attestation, a
Sigstore-transparency-log code measurement, and TLS key binding.
Re-implementing that in a weaker homegrown check would be strictly worse, so this
verifier is the ONLY path allowed to report ``sdk-verified``.

We bind the SDK's verification document to the route, Tinfoil's official verifier,
and Tinfoil's exact signed GitHub release authority. This removes AnonRouter's
second per-release fingerprint allowlist without weakening the provider's own
fail-closed verification.

Verdict-for-verdict equivalent to the Tinfoil verifier in ``@anonrouter/confidential``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .._util import as_dict
from .checks import (
    assemble_result,
    check,
    freshness_check,
    hex_equal,
    read_envelope,
)
from .types import AttestationExpectations, NormalizedVerdict

VERIFIER_VERSION = "tinfoil-sdk/1"


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
    """Validate a Tinfoil verification document against its release authority.

    What this proves, precisely: the document reports a successful Tinfoil SDK
    verification, and its release identity came from Tinfoil's exact signed GitHub
    repository and tagged release workflow. The
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

    verifier_identity = as_dict(doc.get("verifier"))
    verifier_identity_ok = (
        doc.get("schemaVersion") == 1
        and verifier_identity.get("name") == "@tinfoilsh/verifier"
        and isinstance(verifier_identity.get("version"), str)
        and len(verifier_identity["version"]) > 0
    )
    checks.append(check("official_verifier_identity", verifier_identity_ok, True,
                        None if verifier_identity_ok else "verification document is not from the official Tinfoil verifier"))

    selected_router_host = _host_from_url(doc.get("selectedRouterEndpoint"))
    host_ok = selected_router_host == expectations.endpoint_identity
    checks.append(check("enclave_host_binding", host_ok, True,
                        None if host_ok else "attested enclave host does not match route endpoint"))

    steps = as_dict(doc.get("steps"))
    required_steps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"]
    steps_ok = all(as_dict(steps.get(name)).get("status") == "success" for name in required_steps)
    checks.append(check("sdk_verification_steps", steps_ok, True,
                        None if steps_ok else "one or more SDK cryptographic steps did not succeed"))

    authority = as_dict(as_dict(expectations.measurement_policy).get("accepted"))
    authority_ok = (
        authority.get("authority") == "github-actions-sigstore"
        and authority.get("configRepo") == "tinfoilsh/confidential-model-router"
        and authority.get("releaseSelection") == "latest"
        and authority.get("requireTaggedRelease") is True
        and doc.get("configRepo") == authority.get("configRepo")
    )
    checks.append(check("provider_release_authority", authority_ok, True,
                        None if authority_ok else "release is not bound to the supported Tinfoil GitHub authority"))

    release_tag = doc.get("releaseTag")
    release_digest = doc.get("releaseDigest")
    code_fingerprint = doc.get("codeFingerprint")
    enclave_fingerprint = doc.get("enclaveFingerprint")
    release_identity_ok = (
        isinstance(release_tag, str) and len(release_tag) > 0
        and isinstance(release_digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", release_digest) is not None
        and isinstance(code_fingerprint, str) and re.fullmatch(r"[0-9a-fA-F]{64,192}", code_fingerprint) is not None
        and isinstance(enclave_fingerprint, str) and re.fullmatch(r"[0-9a-fA-F]{64,192}", enclave_fingerprint) is not None
    )
    checks.append(check("signed_release_identity", release_identity_ok, True,
                        None if release_identity_ok else "signed release identity is missing or malformed"))

    measurement_ok = hex_equal(_str_or_none(code_fingerprint), _str_or_none(enclave_fingerprint))
    checks.append(check("code_matches_live_enclave", measurement_ok, True,
                        None if measurement_ok else "signed release measurement does not match the live enclave"))

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
            isinstance(tls_fingerprint, str)
            and re.fullmatch(r"[0-9a-fA-F]{64}", tls_fingerprint) is not None
            and hex_equal(tls_fingerprint, _str_or_none(tls_public_key))
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
