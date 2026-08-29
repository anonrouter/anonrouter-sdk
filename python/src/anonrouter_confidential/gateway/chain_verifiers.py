"""Reference DCAP chain-verifier adapters.

This package deliberately ships no DCAP engine: a real one needs Intel's QVL and
collateral, and pretending otherwise would let the SDK report ``hardware_verified``
for work it never did. ``verify_gateway_attestation`` therefore takes a
``chain_verifier`` port, and these are the two maintained ways to fill it.

``SubprocessChainVerifier``  spawn a DCAP verifier executable you control and read
                             its JSON verdict. The strong option: trust stays on
                             your machine.
``RemoteChainVerifier``      POST the quote to a Quote Verification Service.
                             Convenient, and a REAL trust transfer: you are now
                             trusting that service's answer about whether the
                             hardware is genuine. Never point it at a service run
                             by the party you are verifying.

FAIL CLOSED, ALWAYS. Every failure mode means "not verified": a missing binary, a
timeout, a crash, a non-zero exit, output that is not JSON, output that is too
large, a malformed verdict, an unreachable service. There is no path where an
error becomes a pass, and none of these raise into the verifier.

Mirrors ``js/confidential/src/gateway/chain-verifiers.ts``.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

#: A verdict is small; anything larger means something is wrong.
MAX_OUTPUT_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class DcapEngineVerdict:
    """The JSON an engine must print on stdout.

    Matches the shape AnonRouter's own ``native/dcap-verifier`` emits, so an
    operator can point either language at the same binary and get the same answer.
    """

    verified: bool
    tcb_status: str | None = None
    error: str | None = None


def parse_engine_verdict(stdout: str) -> DcapEngineVerdict | None:
    """Parse an engine's stdout, or None if it is unusable."""
    if not stdout or len(stdout) > MAX_OUTPUT_BYTES:
        return None
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    verified = parsed.get("verified")
    # ``verified`` must be a real boolean. A truthy string or a missing field is a
    # malformed verdict, and coercing it would invent a pass out of noise.
    if not isinstance(verified, bool):
        return None
    status = parsed.get("tcbStatus")
    error = parsed.get("error")
    return DcapEngineVerdict(
        verified=verified,
        tcb_status=status if isinstance(status, str) else None,
        error=error if isinstance(error, str) else None,
    )


class PreparedChainVerifier:
    """A verdict bound to the exact quote it describes.

    The quote check is load-bearing. Without it, a verifier prepared for quote A
    would report verified for quote B, which is the substitution the whole port
    exists to prevent.
    """

    def __init__(self, quote: str, verdict: DcapEngineVerdict, implementation: str) -> None:
        self._quote = quote.lower()
        self._verdict = verdict
        self.implementation = implementation

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None]:
        if not isinstance(quote, str) or quote.lower() != self._quote:
            return False, None
        return bool(self._verdict.verified), self._verdict.tcb_status


def _is_hex(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) > 0
        and len(value) % 2 == 0
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


class SubprocessChainVerifier:
    """Verify quotes by spawning a DCAP engine you control.

    ``binary_path`` is REQUIRED and never inferred: silently verifying with an
    engine the caller did not name is exactly the substitution this component
    exists to prevent.
    """

    def __init__(
        self,
        binary_path: str,
        *,
        args: list[str] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        implementation: str | None = None,
    ) -> None:
        self.binary_path = binary_path
        self.args = list(args or [])
        self.timeout_seconds = timeout_seconds
        self.implementation = implementation or f"subprocess:{binary_path}"

    def prepare(self, quote: str) -> PreparedChainVerifier:
        """Run the engine for one quote and return a verifier bound to it."""
        verdict = self._run(quote)
        return PreparedChainVerifier(quote, verdict, self.implementation)

    def _run(self, quote: str) -> DcapEngineVerdict:
        if not _is_hex(quote):
            return DcapEngineVerdict(False, None, "quote is not even-length hex")
        try:
            # The quote goes on stdin, never argv: a multi-kilobyte hex blob in a
            # command line is a process-listing leak and an ARG_MAX hazard.
            completed = subprocess.run(
                [self.binary_path, *self.args],
                input=quote,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            return DcapEngineVerdict(False, None, "engine binary not found")
        except subprocess.TimeoutExpired:
            return DcapEngineVerdict(False, None, "engine timed out")
        except OSError:
            return DcapEngineVerdict(False, None, "engine could not be spawned")
        if completed.returncode != 0:
            return DcapEngineVerdict(False, None, f"engine exited {completed.returncode}")
        parsed = parse_engine_verdict((completed.stdout or "").strip())
        return parsed or DcapEngineVerdict(False, None, "engine produced no usable verdict")


class RemoteChainVerifier:
    """Verify quotes by asking a remote Quote Verification Service.

    TRUST NOTE: this moves the "is this real silicon" decision to that service.
    Pointing it at anything operated by the party you are verifying makes the whole
    check circular, and the SDK cannot detect that for you.
    """

    def __init__(
        self,
        url: str,
        *,
        http_client: Any = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        headers: dict[str, str] | None = None,
        implementation: str | None = None,
    ) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.headers = dict(headers or {})
        self.implementation = implementation or f"remote:{url}"
        self._http = http_client

    def prepare(self, quote: str) -> PreparedChainVerifier:
        verdict = self._run(quote)
        return PreparedChainVerifier(quote, verdict, self.implementation)

    def _run(self, quote: str) -> DcapEngineVerdict:
        import httpx

        client = self._http or httpx.Client(timeout=self.timeout_seconds)
        try:
            response = client.post(
                self.url,
                json={"quote": quote},
                headers={"content-type": "application/json", **self.headers},
            )
        except httpx.HTTPError:
            return DcapEngineVerdict(False, None, "verification service was unreachable")
        finally:
            if self._http is None:
                client.close()
        if response.status_code >= 400:
            return DcapEngineVerdict(
                False, None, f"verification service returned {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError:
            return DcapEngineVerdict(False, None, "verification service returned non-JSON")
        parsed = parse_engine_verdict(json.dumps(body))
        return parsed or DcapEngineVerdict(
            False, None, "verification service returned no usable verdict"
        )
