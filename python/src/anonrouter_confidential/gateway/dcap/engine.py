"""The official DCAP chain-verifier adapter.

This is the answer to "how does an ordinary user reach ``hardware_verified``?".
It drives AnonRouter's reviewed offline DCAP engine (``anonrouter-dcap-verifier``,
dcap-qvl 0.6.1, no network, pinned Intel root, explicit TCB gate) across a process
boundary, and it is the only adapter in this package that speaks that engine's
exact wire contract.

WHY NO ENGINE IS BUNDLED, STATED PLAINLY

A real DCAP verifier is native code. Shipping one inside a wheel would mean
publishing prebuilt binaries for every platform, and this package cannot honestly
assert that a binary it did not build reproducibly is the reviewed engine. A
hand-rolled Python reimplementation would be worse: it would be an unreviewed,
un-cross-checked implementation of the one component whose failure mode is
"reports hardware_verified for a forged quote". So the engine stays a separate,
reviewed artifact you install, and this module is a strict, fail-closed adapter to
it. ``describe_dcap_installation()`` says exactly what to install and where this
module will look.

THE WIRE CONTRACT (engine request v1)

    stdin   {"v":1,"quote":"<hex>","collateral":{...},"now_secs":N,
             "accepted_tcb_statuses":["UpToDate"]}
    stdout  {"v":1,"verified":bool,"tcb_status":"...","qe_tcb_status":"...",
             "platform_tcb_status":"...","advisory_ids":[],"report":{...},
             "error":null,"engine":"anonrouter-dcap-verifier/x dcap-qvl/y"}
    exit    0 verified, 1 not verified, 2 unusable input

The exit code is NOT the answer: the engine prints a verdict for both 0 and 1. The
verdict is parsed first and ``verified`` must be exactly ``True``.

FAIL CLOSED, ALWAYS. A missing binary, a digest that does not match the pin, a
timeout, a crash, output that is not JSON, output that is too large, a ``verified``
field that is not a real bool, collateral that could not be acquired, or an engine
report that disagrees with the quote we parsed all resolve to not-verified.

Mirrors ``js/confidential/src/gateway/dcap/engine.ts``.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as _platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from ...tdx import parse_tdx_quote
from .collateral import (
    CollateralCache,
    CollateralError,
    DcapCollateral,
    normalize_quote_hex,
)

#: The program name the engine is published under.
DCAP_ENGINE_PROGRAM = "anonrouter-dcap-verifier"
#: The environment variable an operator sets to point at an installed engine.
DCAP_ENGINE_ENV = "ANONROUTER_DCAP_VERIFIER_BIN"
#: The request wire version this adapter speaks.
DCAP_ENGINE_REQUEST_VERSION = 1

#: A verdict is small; anything larger means something is wrong.
MAX_OUTPUT_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class DcapEngineVerdictV1:
    """The engine's v1 verdict, normalized. Every optional field becomes explicit."""

    verified: bool
    tcb_status: str | None = None
    qe_tcb_status: str | None = None
    platform_tcb_status: str | None = None
    advisory_ids: list[str] = field(default_factory=list)
    report: dict[str, Any] | None = None
    #: Content-free reason, present when ``verified`` is False.
    error: str | None = None
    #: Which engine produced this, for the audit trail.
    engine: str = "unknown"


def build_dcap_engine_request(
    quote_hex: str,
    collateral: DcapCollateral | dict[str, Any],
    now_secs: int,
    accepted_tcb_statuses: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Build the exact request document the engine reads on stdin.

    Pure and exported so the shared known-answer vectors can pin it: if Python and
    JS ever serialized a different request, they would be verifying different
    things while reporting the same verdict shape.
    """
    payload: dict[str, Any] = {
        "v": DCAP_ENGINE_REQUEST_VERSION,
        "quote": quote_hex,
        "collateral": collateral.as_dict()
        if isinstance(collateral, DcapCollateral)
        else dict(collateral),
        "now_secs": int(now_secs),
    }
    if accepted_tcb_statuses:
        payload["accepted_tcb_statuses"] = list(accepted_tcb_statuses)
    return payload


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def parse_dcap_engine_verdict(stdout: str) -> DcapEngineVerdictV1 | None:
    """Parse the engine's stdout into a verdict, or None if it is unusable.

    ``verified`` must be a real bool: a truthy string, a 1, or a missing field is a
    malformed verdict, and coercing any of them would invent a pass out of noise.
    """
    if not isinstance(stdout, str) or not stdout or len(stdout) > MAX_OUTPUT_BYTES:
        return None
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    verified = parsed.get("verified")
    if not isinstance(verified, bool):
        return None
    report = parsed.get("report")
    advisories = parsed.get("advisory_ids")
    return DcapEngineVerdictV1(
        verified=verified,
        tcb_status=_string_or_none(parsed.get("tcb_status")),
        qe_tcb_status=_string_or_none(parsed.get("qe_tcb_status")),
        platform_tcb_status=_string_or_none(parsed.get("platform_tcb_status")),
        advisory_ids=[a for a in advisories if isinstance(a, str)]
        if isinstance(advisories, list)
        else [],
        report=report if isinstance(report, dict) else None,
        error=_string_or_none(parsed.get("error")),
        engine=_string_or_none(parsed.get("engine")) or "unknown",
    )


# ---- Locating the engine ------------------------------------------------------


@dataclass(frozen=True)
class ResolvedDcapBinary:
    path: str | None
    #: "explicit", "environment", "path", or "none".
    origin: str
    #: Why nothing was resolved, when ``path`` is None.
    reason: str | None


def _is_executable_file(candidate: str) -> bool:
    return os.path.isfile(candidate) and os.access(candidate, os.X_OK)


def resolve_dcap_verifier_binary(
    explicit: str | None = None,
    *,
    search_path: bool = True,
    env: dict[str, str] | None = None,
) -> ResolvedDcapBinary:
    """Resolve which engine to run.

    Order: an explicit path, then ``ANONROUTER_DCAP_VERIFIER_BIN``, then the exact
    program name on PATH. All three are choices an operator made.

    THE LOAD-BEARING RULE: a source that is named but unusable resolves to NOTHING.
    An explicit path that does not exist does not fall through to the environment,
    and an environment variable that does not exist does not fall through to PATH.
    Silently verifying with an engine the caller did not name is exactly the
    substitution this component exists to prevent.
    """
    environment = os.environ if env is None else env
    if explicit:
        if _is_executable_file(explicit):
            return ResolvedDcapBinary(explicit, "explicit", None)
        return ResolvedDcapBinary(
            None, "none", f"the requested engine {explicit} is not an executable file"
        )
    from_env = environment.get(DCAP_ENGINE_ENV)
    if from_env:
        if _is_executable_file(from_env):
            return ResolvedDcapBinary(from_env, "environment", None)
        return ResolvedDcapBinary(
            None,
            "none",
            f"{DCAP_ENGINE_ENV} points at {from_env}, which is not an executable file",
        )
    if not search_path:
        return ResolvedDcapBinary(None, "none", f"no engine given and {DCAP_ENGINE_ENV} is unset")
    found = shutil.which(DCAP_ENGINE_PROGRAM, path=environment.get("PATH"))
    if found:
        return ResolvedDcapBinary(found, "path", None)
    return ResolvedDcapBinary(
        None,
        "none",
        f"no {DCAP_ENGINE_PROGRAM} found: set {DCAP_ENGINE_ENV} or put it on PATH",
    )


def file_sha256(path: str) -> str | None:
    """SHA-256 of a file, lowercase hex, or None when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            return digest.hexdigest()
    except OSError:
        return None


def dcap_platform_target(
    system: str | None = None, machine: str | None = None
) -> str | None:
    """The Rust target triple for the current host, or None when it is not one we name."""
    plat = (system or sys.platform).lower()
    arch = (machine or _platform.machine()).lower()
    if arch in ("amd64", "x86_64"):
        arch = "x86_64"
    elif arch in ("arm64", "aarch64"):
        arch = "aarch64"
    if plat.startswith("linux"):
        return f"{arch}-unknown-linux-gnu" if arch in ("x86_64", "aarch64") else None
    if plat == "darwin":
        return f"{arch}-apple-darwin" if arch in ("x86_64", "aarch64") else None
    if plat.startswith("win"):
        return "x86_64-pc-windows-msvc" if arch == "x86_64" else None
    return None


@dataclass(frozen=True)
class DcapInstallationReport:
    available: bool
    binary_path: str | None
    origin: str
    binary_sha256: str | None
    target: str | None
    platform: str
    arch: str
    reason: str | None
    instructions: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "binary_path": self.binary_path,
            "origin": self.origin,
            "binary_sha256": self.binary_sha256,
            "target": self.target,
            "platform": self.platform,
            "arch": self.arch,
            "reason": self.reason,
            "instructions": list(self.instructions),
        }


def describe_dcap_installation(
    *,
    binary_path: str | None = None,
    search_path: bool = True,
    env: dict[str, str] | None = None,
) -> DcapInstallationReport:
    """Report whether the engine is installed, and say exactly what to do if not.

    This is what the ``doctor`` command prints. It never reads or echoes any
    credential, and it never guesses: the reported path is the one that would
    actually be executed.
    """
    resolved = resolve_dcap_verifier_binary(binary_path, search_path=search_path, env=env)
    target = dcap_platform_target()
    if resolved.path:
        instructions = [
            f"Engine resolved from {resolved.origin}: {resolved.path}",
            "Compare its SHA-256 against the digest published with the release you intend to run.",
            "Pin it in code with expected_binary_sha256 so a swapped binary fails closed.",
        ]
    else:
        where = target or f"{sys.platform}/{_platform.machine()} (not a named target)"
        instructions = [
            (
                "This package bundles no DCAP engine, by design: it cannot honestly assert "
                "that a binary it did not build reproducibly is the reviewed one."
            ),
            f"Install the {DCAP_ENGINE_PROGRAM} release artifact for {where}.",
            (
                f"Then either put it on PATH under the name {DCAP_ENGINE_PROGRAM}, or set "
                f"{DCAP_ENGINE_ENV} to its absolute path, or pass binary_path explicitly."
            ),
            (
                "Verify the artifact's SHA-256 against the digest published alongside it, "
                "obtained independently of the gateway you are verifying."
            ),
            (
                "Without an engine, verification is capped at cryptographically_checked and "
                "a policy requiring hardware verification fails closed. It never silently "
                "downgrades."
            ),
        ]
    return DcapInstallationReport(
        available=resolved.path is not None,
        binary_path=resolved.path,
        origin=resolved.origin,
        binary_sha256=file_sha256(resolved.path) if resolved.path else None,
        target=target,
        platform=sys.platform,
        arch=_platform.machine(),
        reason=resolved.reason,
        instructions=instructions,
    )


# ---- Running the engine -------------------------------------------------------


def run_dcap_engine(
    binary_path: str,
    request: dict[str, Any],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> DcapEngineVerdictV1:
    """Run the engine once over a fully-formed request. Never raises."""
    payload = json.dumps(request)
    failure: str | None = None
    stdout = ""
    try:
        # No shell, so nothing in the request can be interpreted as a command. The
        # request travels on stdin, never argv, so a quote never appears in the
        # process table.
        completed = subprocess.run(
            [binary_path],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = (completed.stdout or "")[:MAX_OUTPUT_BYTES]
    except FileNotFoundError:
        failure = "engine binary not found"
    except subprocess.TimeoutExpired:
        failure = "engine timed out"
    except OSError:
        failure = "engine could not be spawned"

    # A non-zero exit is EXPECTED for "not verified", and the engine still prints a
    # verdict, so the exit code is not the answer. Parse first.
    verdict = parse_dcap_engine_verdict(stdout.strip())
    if verdict is not None:
        return verdict
    return DcapEngineVerdictV1(
        verified=False,
        error=f"engine produced no usable verdict ({failure})"
        if failure
        else "engine produced no usable verdict",
        engine="unavailable",
    )


def engine_report_disagreement(quote_hex: str, report: dict[str, Any] | None) -> str | None:
    """Cross-check the engine's own view of the TD against the quote we parsed.

    The engine and this SDK read the same bytes independently. If they disagree
    about mr_td, the RTMRs, or report_data, then one of them is not looking at the
    quote the caller is about to trust, and the only safe reading of that is
    refusal. Returns a content-free reason, or None when they agree.
    """
    if not report:
        return None
    parsed = parse_tdx_quote(quote_hex)
    if parsed is None:
        return "the SDK could not parse the quote the engine verified"

    def same(key: str, expected: str) -> bool:
        value = report.get(key)
        return isinstance(value, str) and value.lower() == expected.lower()

    for key, expected in (
        ("mr_td", parsed.mr_td),
        ("mr_config_id", parsed.mr_config_id),
        ("rtmr0", parsed.rtmr0),
        ("rtmr1", parsed.rtmr1),
        ("rtmr2", parsed.rtmr2),
        ("rtmr3", parsed.rtmr3),
        ("report_data", parsed.report_data),
    ):
        if not same(key, expected):
            return f"engine and SDK disagree about {key}"
    return None


class PreparedDcapVerifier:
    """A verifier bound to one quote, replaying an engine verdict for exactly it."""

    def __init__(self, quote_hex: str, verdict: DcapEngineVerdictV1, implementation: str) -> None:
        self._quote = quote_hex.lower()
        self._verdict = verdict
        self.implementation = implementation

    @property
    def verdict(self) -> DcapEngineVerdictV1:
        """The engine verdict this verifier replays, for reporting."""
        return self._verdict

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None, str]:
        # Compare on BYTES, not spelling: evidence may arrive base64 where the
        # engine was prepared from hex, and a spelling mismatch must not read as a
        # substituted quote.
        offered = normalize_quote_hex(quote)
        if offered is None or offered != self._quote:
            return False, None, "this verifier was prepared for a different quote"
        if self._verdict.verified:
            detail = (
                f"engine={self.implementation} "
                f"qe={self._verdict.qe_tcb_status or '?'} "
                f"platform={self._verdict.platform_tcb_status or '?'}"
            )
            return True, self._verdict.tcb_status, detail
        return False, self._verdict.tcb_status, self._verdict.error or "engine refused the quote"


def _refusing_verifier(quote_hex: str, reason: str, implementation: str) -> PreparedDcapVerifier:
    return PreparedDcapVerifier(
        quote_hex,
        DcapEngineVerdictV1(verified=False, error=reason, engine=implementation),
        implementation,
    )


class AnonRouterDcapVerifier:
    """The recommended production adapter.

    A FACTORY: the client prepares it against the exact quote it just fetched, and
    passes the policy's accepted TCB statuses in, so the engine and the local policy
    cannot disagree about what "acceptable" means. The prepared verifier answers
    only for that quote.
    """

    def __init__(
        self,
        *,
        binary_path: str | None = None,
        search_path: bool = True,
        expected_binary_sha256: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        collateral: DcapCollateral | dict[str, Any] | None = None,
        fetch_collateral: bool = True,
        collateral_cache: CollateralCache | None = None,
        pcs_base: str | None = None,
        cert_base: str | None = None,
        http_client: Any = None,
        implementation: str | None = None,
    ) -> None:
        self.binary_path = binary_path
        self.search_path = search_path
        self.expected_binary_sha256 = expected_binary_sha256
        self.timeout_seconds = timeout_seconds
        self.collateral = collateral
        self.fetch_collateral = fetch_collateral
        self.implementation = implementation
        self._pcs_base = pcs_base
        self._cert_base = cert_base
        self._http_client = http_client
        self._cache = collateral_cache or CollateralCache(self._fetch)

    def _fetch(self, quote: str) -> Any:
        from .collateral import INTEL_CERT_BASE, INTEL_PCS_BASE, fetch_intel_collateral

        return fetch_intel_collateral(
            quote,
            pcs_base=self._pcs_base or INTEL_PCS_BASE,
            cert_base=self._cert_base or INTEL_CERT_BASE,
            http_client=self._http_client,
            timeout_seconds=self.timeout_seconds,
        )

    def prepare(
        self,
        quote: str,
        *,
        accepted_tcb_statuses: list[str] | tuple[str, ...] | None = None,
        now_ms: float | None = None,
    ) -> PreparedDcapVerifier:
        quote_hex = normalize_quote_hex(quote)
        if quote_hex is None:
            return _refusing_verifier(
                quote if isinstance(quote, str) else "",
                "quote is neither hex nor base64",
                self.implementation or "unavailable",
            )

        resolved = resolve_dcap_verifier_binary(self.binary_path, search_path=self.search_path)
        if resolved.path is None:
            return _refusing_verifier(
                quote_hex,
                resolved.reason or "no DCAP engine available",
                self.implementation or "unavailable",
            )
        label = self.implementation or f"subprocess:{resolved.path}"
        if self.expected_binary_sha256:
            digest = file_sha256(resolved.path)
            if digest is None or digest != self.expected_binary_sha256.strip().lower():
                return _refusing_verifier(
                    quote_hex,
                    "the resolved engine's SHA-256 does not match expected_binary_sha256",
                    label,
                )

        collateral = self.collateral
        if collateral is None:
            if not self.fetch_collateral:
                return _refusing_verifier(
                    quote_hex, "no collateral supplied and fetching is disabled", label
                )
            try:
                collateral = self._cache.get(quote_hex, now_ms).collateral
            except CollateralError as exc:
                return _refusing_verifier(quote_hex, f"collateral unavailable: {exc}", label)

        moment = time.time() * 1000.0 if now_ms is None else now_ms
        request = build_dcap_engine_request(
            quote_hex, collateral, int(moment // 1000), accepted_tcb_statuses
        )
        verdict = run_dcap_engine(resolved.path, request, self.timeout_seconds)

        # The engine read the same bytes we did. If it reports a different TD, one
        # of us is not looking at the quote about to be trusted.
        if verdict.verified:
            disagreement = engine_report_disagreement(quote_hex, verdict.report)
            if disagreement:
                return _refusing_verifier(quote_hex, disagreement, self.implementation or verdict.engine)
        return PreparedDcapVerifier(quote_hex, verdict, self.implementation or verdict.engine)


def create_anonrouter_dcap_verifier(**options: Any) -> AnonRouterDcapVerifier:
    """Convenience constructor, mirroring the JS ``createAnonRouterDcapVerifier``."""
    return AnonRouterDcapVerifier(**options)
