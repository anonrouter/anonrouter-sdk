"""Credential-free, read-only verification of a GCP content node.

A fresh nonce, the owner-signed release policy v3 (by default the production
owner root packaged with this SDK), native DCAP and the TLS key read from the
same retained socket that fetched the evidence. The socket is closed afterwards;
inference must use ``gateway_connection_binding`` to retain its own verified
socket. Requires the ``connection-binding`` extra (the reviewed HTTPX/HTTPCore
pair). Mirrors the JavaScript ``verifyContentNode``.
"""

from __future__ import annotations

import threading
from typing import Any

from ..errors import ConfidentialError
from .release_v3 import ReleasePolicyV3Source
from .retained_sync import RetainedGatewayConnection

DEFAULT_CONTENT_ORIGIN = "https://api.anonrouter.ai"


def _provenance(approval: dict[str, Any]) -> dict[str, Any]:
    policy = approval["policy"]
    return {
        "origin": "signed-release-policy-v3", "source": policy.source, "version": policy.version,
        "sequence": approval["sequence"], "payloadSha256": approval["payloadSha256"],
        "ownerRootSha256": approval["release"]["ownerRootSha256"], "deploymentId": approval["release"]["deploymentId"],
    }


def verify_content_node(
    origin: str = DEFAULT_CONTENT_ORIGIN, *, policy_source: ReleasePolicyV3Source | None = None,
    chain_verifier: Any = None, cancel_event: threading.Event | None = None, timeout: float = 120.0,
) -> dict[str, Any]:
    """Return ``{"origin", "policy", "verdict", "raw_evidence"}``.

    ``verdict.status`` is "ok" only when every required check passed on the
    retained socket. A failed verdict is returned (not raised) when evidence was
    fetched and judged, with ``raw_evidence`` None; feed, transport and
    configuration failures raise.
    """
    owned = policy_source is None
    source = policy_source if policy_source is not None else ReleasePolicyV3Source()
    try:
        if chain_verifier is None:
            from .dcap import create_anonrouter_dcap_verifier
            chain_verifier = create_anonrouter_dcap_verifier()
        approval = source.resolve(origin)

        def refresh() -> tuple[Any, float | None]:
            nonlocal approval
            approval = source.resolve(origin, force_refresh=True)
            return approval["policy"], approval["expiresAtMs"]

        try:
            connection = RetainedGatewayConnection(
                origin=origin, policy=approval["policy"], chain_verifier=chain_verifier,
                approval_expires_at_ms=approval["expiresAtMs"], cancel_event=cancel_event, timeout=timeout,
                refresh_policy=refresh)
        except ConfidentialError as error:
            verdict = getattr(error, "verdict", None)
            if verdict is not None:
                return {"origin": origin, "policy": _provenance(approval), "verdict": verdict, "raw_evidence": None}
            raise
        try:
            return {"origin": origin, "policy": _provenance(approval), "verdict": connection.verdict,
                    "raw_evidence": connection.raw_evidence}
        finally:
            connection.close()
    finally:
        if owned:
            source.close()
