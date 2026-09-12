"""Tinfoil verifier.

Tinfoil's own verifier performs the hard cryptographic work: AMD SEV-SNP hardware
attestation, a Sigstore-transparency-log code measurement, and the enclave key
binding. Re-implementing that in a weaker homegrown check would be strictly
worse, so this verifier is the ONLY path allowed to report ``sdk-verified``.

We bind the SDK's verification document to the route, Tinfoil's official verifier,
and Tinfoil's exact signed GitHub release authority. This removes AnonRouter's
second per-release fingerprint allowlist without weakening the provider's own
fail-closed verification.

What this verifier does NOT establish, and must never be read as establishing: no
NVIDIA GPU confidential-compute evidence is checked anywhere on this route, and
nothing binds the model weights. The hardware claim is AMD SEV-SNP alone.

The serving TLS key is the one place where a document can look self-proving and
not be. The official document repeats the SAME AMD-report field as
``enclaveMeasurement.tlsPublicKeyFingerprint`` and ``tlsPublicKey``, so comparing
those two to each other is a tautology: it passes for any document, including one
an endpoint substitution forged wholesale. The attested fingerprint is therefore
only accepted against a ``transportBinding`` that whoever produced the document
recorded from a REAL pinned connection to the enclave. A document carrying no
such observation fails closed, however well formed it is.

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

#: The one Tinfoil endpoint this SDK supports. Fixed, not caller-supplied: an
#: endpoint the caller could name is an endpoint an attacker could name.
TINFOIL_ENDPOINT_IDENTITY = "inference.tinfoil.sh"


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

    What this proves, precisely: the document reports a successful Tinfoil
    verification for the exact repository this package supports, the signed code
    equals the live enclave, and the serving connection's observed TLS key equals
    the key in the verified AMD report. The hard cryptography (AMD SEV-SNP
    attestation, the Sigstore transparency-log measurement, the enclave key
    binding) was done by Tinfoil's own verifier, which produced this document. In
    the client flow the gateway supplies it, including the transport observation,
    so this path does not prove the document independently of AnonRouter. That
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

    # The official verifier is the crypto root of trust for the EVIDENCE: it
    # verified the AMD SEV-SNP report, the signed release provenance, and
    # code/enclave equality, or refused. It cannot vouch for the connection this
    # route is served over, which is why ``attested_key_binding`` below needs an
    # observation instead.
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

    # BOTH endpoint identities the document carries must be the fixed Tinfoil
    # host, and so must the route being verified. Checking only
    # ``selectedRouterEndpoint`` left ``enclaveHost`` free to name somewhere else,
    # and comparing either field to a caller-supplied endpoint would be a
    # tautology that accepts whatever host the document itself chose.
    selected_router_host = _host_from_url(doc.get("selectedRouterEndpoint"))
    enclave_host = _host_from_url(doc.get("enclaveHost"))
    host_ok = (
        selected_router_host == TINFOIL_ENDPOINT_IDENTITY
        and enclave_host == TINFOIL_ENDPOINT_IDENTITY
        and expectations.endpoint_identity == TINFOIL_ENDPOINT_IDENTITY
    )
    checks.append(check("enclave_host_binding", host_ok, True,
                        None if host_ok else "attested enclave host does not match route endpoint"))

    steps = as_dict(doc.get("steps"))
    required_steps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"]
    steps_ok = all(as_dict(steps.get(name)).get("status") == "success" for name in required_steps)
    checks.append(check("sdk_verification_steps", steps_ok, True,
                        None if steps_ok else "one or more SDK cryptographic steps did not succeed"))

    # Read the four policy fields for what they are. ``configRepo`` is
    # load-bearing here: it is compared against the repository the document
    # names, so a different repository fails closed. ``authority``,
    # ``releaseSelection`` and ``requireTaggedRelease`` are LABELS. They record
    # which Tinfoil workflow this package was reviewed against and pin the policy
    # file against a silent edit; nothing in this SDK re-derives them from the
    # evidence, because the document does not carry the Fulcio identity or
    # workflow ref they would be checked against. The tagged-release and
    # release-selection guarantees are the official verifier's, exercised by
    # ``verifyCode`` / ``fetchDigest``, and that is where they are enforced. Do
    # not describe them as independent SDK checks.
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

    # The wired TLS modality must bind the ACTUAL serving connection. The
    # attested fingerprint on its own is not enough, and neither is the document
    # agreeing with itself: ``tlsPublicKeyFingerprint`` and ``tlsPublicKey`` are
    # two copies of one AMD-report field, so comparing them passes for every
    # document ever produced. Require instead a transport binding recorded from a
    # real pinned connection, and require the key observed there to equal the key
    # in the verified report.
    enclave_measurement = as_dict(doc.get("enclaveMeasurement"))
    hpke_public_key = enclave_measurement.get("hpkePublicKey") or doc.get("hpkePublicKey")
    tls_fingerprint = enclave_measurement.get("tlsPublicKeyFingerprint")
    binding = as_dict(doc.get("transportBinding"))
    e2ee = expectations.privacy_modality == "e2ee"
    if e2ee:
        key_ok = isinstance(hpke_public_key, str) and len(hpke_public_key) > 0
    else:
        key_ok = (
            isinstance(tls_fingerprint, str)
            and re.fullmatch(r"[0-9a-fA-F]{64}", tls_fingerprint) is not None
            and binding.get("mode") == "tls-pinned"
            and binding.get("verified") is True
            and binding.get("endpointIdentity") == TINFOIL_ENDPOINT_IDENTITY
            and hex_equal(tls_fingerprint, _str_or_none(binding.get("observedTlsSpki")))
        )
    key_detail = (
        "no attested HPKE key for the client-opaque modality"
        if e2ee
        else "attested TLS key is missing, or was not confirmed by an observed "
             "pinned connection to the enclave"
    )
    checks.append(check("attested_key_binding", key_ok, True, None if key_ok else key_detail))

    checks.append(check("nonce_binding", False, False, "Tinfoil attestation is connection-bound, not nonce-bound"))
    checks.append(freshness_check(envelope.fetched_at_ms, expectations))

    measurements: dict[str, str] = {}
    if doc and isinstance(doc.get("codeFingerprint"), str):
        measurements["code"] = doc["codeFingerprint"]
    if doc and isinstance(doc.get("enclaveFingerprint"), str):
        measurements["enclave"] = doc["enclaveFingerprint"]

    return assemble_result(
        expectations=expectations,
        # AMD SEV-SNP alone. The official verifier establishes no NVIDIA GPU
        # confidential-compute evidence, so reporting a combined hardware type
        # would claim a chain nobody checked.
        hardware_type="amd-sev-snp",
        requested_level="sdk-verified",
        measurement_identities=measurements,
        # The document proves the release/code measurement and the enclave keys.
        # It exposes no model-weight digest, so never invent one from the
        # requested model id.
        model_weight_identity=None,
        attested_tls_spki=_str_or_none(tls_fingerprint),
        attested_encryption_key=None,
        attested_signing_key=None,
        bound_nonce=None,
        verifier_version=VERIFIER_VERSION,
        supports_client_opaque_e2ee=False,
        checks=checks,
    )
