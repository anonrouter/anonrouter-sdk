"""Provider-neutral entry point: dispatch raw evidence to the right verifier."""

from __future__ import annotations

from typing import Any

from .checks import failed_result
from .chutes import verify_chutes
from .near import verify_near
from .tinfoil import verify_tinfoil
from .types import AttestationExpectations, NormalizedVerdict
from .venice import verify_venice

_VERIFIERS = {
    "near-ai": verify_near,
    "venice": verify_venice,
    "chutes": verify_chutes,
    "tinfoil": verify_tinfoil,
}


def verify_raw_evidence(
    provider: str, raw_evidence: Any, expectations: AttestationExpectations
) -> NormalizedVerdict:
    """Independently verify raw provider evidence against ``expectations`` and return
    the NormalizedVerdict. Pure over its inputs (except an injectable clock). Fails
    closed: an unknown provider or malformed evidence yields ``status == "failed"``.

    The verification ceiling is ``provider-attested`` for NEAR/Venice/Chutes and
    ``sdk-verified`` for Tinfoil. It NEVER emits ``hardware-verified``.
    """
    verifier = _VERIFIERS.get(provider)
    if verifier is None:
        # Same fail-closed shape the JavaScript package returns: check detail
        # "provider_not_verifiable", verifier version "sdk/1". Pinned by the
        # "unknown provider" case in shared/vectors/attestation.json.
        return failed_result(expectations, "provider_not_verifiable", "sdk/1")
    return verifier(raw_evidence, expectations)
