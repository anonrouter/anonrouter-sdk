"""Operation-owned sync connection; pin provenance is a fully verified quote."""
from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ..errors import ConfidentialError
from .policy import GatewayMeasurementPolicy
from .transport_sync import SpkiBoundGatewayTransport
from .verify import GatewayVerificationResult


@dataclass(frozen=True)
class GatewayConnectionIdentity:
    origin: str
    tls_spki_sha256: str
    app_id: str
    instance_id: str
    compose_hash: str
    expires_at_ms: float


class VerifiedGatewayConnection:
    def __init__(self, *, origin: str, verdict: GatewayVerificationResult,
                 policy: GatewayMeasurementPolicy, evidence_issued_at_ms: Any,
                 approval_expires_at_ms: float | None = None,
                 cancel_event: threading.Event | None = None, timeout: float = 300.0) -> None:
        binding = verdict.binding
        if (verdict.status != "ok" or verdict.verification_level != "hardware-verified"
                or verdict.tcb_status != "UpToDate" or binding is None or binding.origin != origin
                or binding.transport != "in-tee-tls" or not isinstance(binding.tls_spki_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", binding.tls_spki_sha256)
                or not any(c.name == "quote_signature_chain" and c.passed for c in verdict.checks)
                or any(c.required and not c.passed for c in verdict.checks)
                or type(evidence_issued_at_ms) is not int or evidence_issued_at_ms < 0
                or (approval_expires_at_ms is not None and (type(approval_expires_at_ms) not in {int, float}
                    or not math.isfinite(approval_expires_at_ms) or approval_expires_at_ms <= 0))):
            raise ConfidentialError("a fully verified gateway identity is required for connection binding")
        self.report: dict[str, Any] = {}
        self._identity = GatewayConnectionIdentity(origin, binding.tls_spki_sha256, binding.app_id,
            binding.instance_id, binding.compose_hash,
            min(evidence_issued_at_ms + policy.max_evidence_age_ms, approval_expires_at_ms if approval_expires_at_ms is not None else float("inf")))
        self._cancel_event = cancel_event or threading.Event()
        self._closed = False
        self.assert_dispatch_allowed()
        self._transport = SpkiBoundGatewayTransport(origin=origin,
            expected_tls_spki_sha256=self.identity.tls_spki_sha256, cancel_event=self.cancel_event,
            request_timeout=timeout, before_http_dispatch=self.assert_dispatch_allowed)
        self.http = httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False,
                                 timeout=timeout)

    @property
    def identity(self) -> GatewayConnectionIdentity:
        return self._identity

    @property
    def cancel_event(self) -> threading.Event:
        return self._cancel_event

    def assert_dispatch_allowed(self) -> None:
        if self._closed or self.cancel_event.is_set():
            raise ConfidentialError("the bound gateway operation was cancelled")
        if time.time() * 1000 >= self.identity.expires_at_ms:
            raise ConfidentialError("the verified gateway approval or evidence expired before dispatch")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.http.close()
