"""Provider-neutral attestation verifiers that produce a NormalizedVerdict.

Verification fails closed: a missing/mismatched required check yields
``status == "failed"``. The verification ceiling is ``provider-attested`` for
NEAR/Venice/Chutes (the DCAP/NRAS chain-to-vendor-roots is deliberately not wired;
faking it would be dishonest) and ``sdk-verified`` for Tinfoil via its official
SDK. This subsystem NEVER emits ``hardware-verified``.
"""

from .registry import verify_raw_evidence
from .types import AttestationCheck, AttestationExpectations, NormalizedVerdict

__all__ = [
    "AttestationCheck",
    "AttestationExpectations",
    "NormalizedVerdict",
    "verify_raw_evidence",
]
