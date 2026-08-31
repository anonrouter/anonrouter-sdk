"""anonrouter-verify: check a route from a terminal, and exit nonzero unless the
assurance you asked for was actually established.

This exists so verification can gate something. A library call that returns a
verdict is useful inside an application; a command that fails a shell is what you
put in front of a deploy, a health check, or a CI job that must not proceed against
an unverified plane.

    anonrouter-verify gateway --origin https://api.private.anonrouter.ai --dcap \\
        --require hardware_verified --policy ./reviewed-policy.json
    echo $?    # 0 met, 1 not met, 2 the command itself was wrong

WHAT IT PRINTS. One JSON document on stdout, always, including on failure, so a
caller can branch on the exit code and still read why. Diagnostics go to stderr.

WHAT IT NEVER PRINTS. No API key, no ticket, no prompt or response content, and no
raw evidence body. The gateway document carries ~66 KB of internal compose
topology; the identity and measurements that matter are extracted, and the rest is
deliberately dropped rather than dumped into somebody's CI log. An API key is read
from an environment variable and never accepted on argv, where it would be visible
in the process table and in shell history.

Byte-for-byte the same JSON document as the JavaScript ``anonrouter-verify``, and
``shared/vectors/cli-contract.json`` pins that so the two cannot drift.

Mirrors ``js/confidential/src/cli.ts``.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import sys
from typing import Any
from urllib.parse import urlsplit

from .client import ConfidentialError, create_client
from .gateway.dcap import create_anonrouter_dcap_verifier, describe_dcap_installation
from .gateway.policy import load_gateway_policy, pinned_gateway_policy_for
from .verify.route import (
    RequestedRoute,
    RouteHopVerdict,
    assemble_route_verdict,
    gateway_hop_verdict,
    hop_not_requested,
    provider_hop_verdict,
)
from .verify.state import TRUSTED_STATES, at_least, describe_state

#: The output contract. Bumped only when the document's shape changes.
SCHEMA = "anonrouter-verify/1"

EXIT_MET = 0
EXIT_NOT_MET = 1
EXIT_USAGE = 2

USAGE = f"""anonrouter-verify: independently verify an AnonRouter route.

  anonrouter-verify gateway --origin <url> [options]
      Verify hop 1 only: is this data plane the reviewed build, in a TDX CVM,
      bound to a fresh nonce and this origin? Credential-free.

  anonrouter-verify route --origin <url> --provider <id> --model <id> [options]
      Verify both hops and cross-bind them to the route. Needs an API key for
      hop 2, read from an environment variable (never from argv).

  anonrouter-verify doctor [--origin <url>]
      Report what this machine can establish: the DCAP engine, its digest, the
      host target, and whether a pin ships for the origin. Contacts nothing
      unless --origin is given.

Options
  --origin <url>            The origin to verify. Required for gateway/route.
  --require <state>         Minimum assurance to exit 0. One of:
                            {", ".join(TRUSTED_STATES)}.
                            Default: cryptographically_checked.
  --policy <file>           A reviewed policy JSON to hold the plane to. Without
                            it the pin this package ships for the origin is used.
  --allow-candidate         Accept a shipped pin whose status is "candidate".
  --dcap                    Chain the quote to Intel's roots with the reviewed
                            engine. Required to reach hardware_verified.
  --dcap-binary <path>      Use this engine explicitly instead of discovering one.
  --dcap-sha256 <hex>       Refuse to run an engine whose SHA-256 differs.
  --collateral <file>       Supply Intel collateral instead of fetching it.
  --no-collateral-fetch     Refuse to fetch collateral. Needs --collateral.
  --no-tls-check            Skip observing this origin's TLS certificate.
  --api-key-env <NAME>      Environment variable holding the API key for hop 2.
                            Default: ANONROUTER_API_KEY.
  --timeout <ms>            Network deadline. Default: 30000.
  --compact                 Print the JSON on one line.
  -h, --help                This text.

Exit codes
  0  the requested assurance was established
  1  it was not (including "we could not look")
  2  the command or its inputs were wrong
"""


class UsageError(Exception):
    """The command or its inputs were wrong. Never a verification outcome."""


_FLAGS_WITH_VALUES = {
    "--origin": "origin",
    "--require": "require",
    "--policy": "policy_file",
    "--dcap-binary": "dcap_binary",
    "--dcap-sha256": "dcap_sha256",
    "--collateral": "collateral_file",
    "--api-key-env": "api_key_env",
    "--timeout": "timeout_ms",
    "--provider": "provider",
    "--model": "model",
    "--upstream-model": "upstream_model",
}


def parse_args(argv: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {
        "command": "doctor",
        "origin": None,
        "require": "cryptographically_checked",
        "policy_file": None,
        "allow_candidate": False,
        "dcap": False,
        "dcap_binary": None,
        "dcap_sha256": None,
        "collateral_file": None,
        "fetch_collateral": True,
        "tls_check": True,
        "api_key_env": "ANONROUTER_API_KEY",
        "timeout_ms": 30_000,
        "compact": False,
        "provider": None,
        "model": None,
        "upstream_model": None,
    }
    if not argv or argv[0] in ("-h", "--help"):
        raise UsageError("")
    command = argv[0]
    if command not in ("gateway", "route", "doctor"):
        raise UsageError(f'unknown command "{command}"')
    options["command"] = command

    rest = argv[1:]
    index = 0
    while index < len(rest):
        flag = rest[index]
        if flag in ("-h", "--help"):
            raise UsageError("")
        if flag in _FLAGS_WITH_VALUES:
            if index + 1 >= len(rest) or rest[index + 1].startswith("--"):
                raise UsageError(f"{flag} needs a value")
            options[_FLAGS_WITH_VALUES[flag]] = rest[index + 1]
            if flag == "--dcap-binary":
                options["dcap"] = True
            index += 2
            continue
        if flag == "--allow-candidate":
            options["allow_candidate"] = True
        elif flag == "--dcap":
            options["dcap"] = True
        elif flag == "--no-collateral-fetch":
            options["fetch_collateral"] = False
        elif flag == "--no-tls-check":
            options["tls_check"] = False
        elif flag == "--compact":
            options["compact"] = True
        elif flag == "--api-key":
            # An API key on argv is visible in the process table and in shell
            # history, so it is refused by name rather than silently ignored.
            raise UsageError(
                "--api-key is refused: pass the key through an environment variable "
                "and name it with --api-key-env"
            )
        else:
            raise UsageError(f'unknown option "{flag}"')
        index += 1

    if options["require"] not in TRUSTED_STATES:
        raise UsageError(f"--require must be one of {', '.join(TRUSTED_STATES)}")
    try:
        options["timeout_ms"] = float(options["timeout_ms"])
    except (TypeError, ValueError) as exc:
        raise UsageError("--timeout must be a positive number of milliseconds") from exc
    if options["timeout_ms"] <= 0:
        raise UsageError("--timeout must be a positive number of milliseconds")
    if options["command"] != "doctor" and not options["origin"]:
        raise UsageError(f"{options['command']} needs --origin")
    if options["command"] == "route" and not (options["provider"] and options["model"]):
        raise UsageError("route needs --provider and --model")
    if options["require"] == "hardware_verified" and not options["dcap"] and options["command"] != "doctor":
        # Better to refuse the command than to run it and report a failure whose
        # cause is that the operator did not ask for the thing they required.
        raise UsageError(
            "--require hardware_verified needs --dcap: without a chain verifier "
            "nothing can reach that state"
        )
    if not options["fetch_collateral"] and not options["collateral_file"]:
        raise UsageError("--no-collateral-fetch needs --collateral <file>")
    return options


def _read_json_file(path: str, what: str) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise UsageError(f"could not read {what} from {path}: {exc}") from exc


def observe_tls_spki(origin: str, timeout_seconds: float) -> str | None:
    """Observe the leaf certificate's SPKI on this origin.

    HONESTY NOTE, carried into the output as ``source``: this opens its own TLS
    connection rather than reading the certificate off the connection that carried
    the attestation request, because the HTTP client does not expose it. Against a
    single origin terminating TLS inside one TD those are the same certificate, and
    a mismatch is still conclusive. Against a fleet presenting different keys per
    connection, agreement is weaker than a same-connection observation would be.
    """
    parts = urlsplit(origin)
    if parts.scheme != "https" or not parts.hostname:
        return None
    port = parts.port or 443
    # The public chain must validate on its own. A CLI that disabled this would be
    # observing a certificate nobody vouched for.
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((parts.hostname, port), timeout=timeout_seconds) as raw,
            context.wrap_socket(raw, server_hostname=parts.hostname) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.x509 import load_der_x509_certificate

        spki = load_der_x509_certificate(der).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:  # noqa: BLE001 - an unreadable certificate is "not observed"
        return None
    return hashlib.sha256(spki).hexdigest()


def _hop_document(hop: RouteHopVerdict) -> dict[str, Any]:
    """Project a hop verdict into the output document. Never carries raw evidence.

    The key names are the JavaScript document's camelCase, not this module's
    snake_case, because the two commands emit ONE contract and a consumer must not
    have to know which language produced it.
    """
    return {
        "requested": hop.requested,
        "state": hop.state,
        "meaning": hop.meaning,
        "reason": hop.reason,
        "failedChecks": list(hop.failed_checks),
        "advisoryGaps": list(hop.advisory_gaps),
    }


def _resolve_policy(options: dict[str, Any]) -> tuple[Any, str]:
    if options["policy_file"]:
        raw = _read_json_file(options["policy_file"], "policy")
        # Accept either a bare policy or a registry entry wrapping one, because
        # both shapes exist in the wild and guessing wrong is a confusing error.
        candidate = raw["policy"] if isinstance(raw, dict) and "policy" in raw else raw
        try:
            return load_gateway_policy(candidate), f"policy loaded from {options['policy_file']}"
        except ValueError as exc:
            raise UsageError(f"policy at {options['policy_file']} is not valid: {exc}") from exc
    return None, "using the pin this package ships for the origin"


def _engine_document(options: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    """The engine block of the output document, plus the report it came from."""
    report = describe_dcap_installation(binary_path=options["dcap_binary"])
    document: dict[str, Any] = {
        "requested": bool(options["dcap"]),
        "available": report.available,
        "binaryPath": report.binary_path,
        "binarySha256": report.binary_sha256,
        "origin": report.origin,
        "target": report.target,
        "reason": report.reason,
    }
    if options["dcap"] and not report.available:
        document["instructions"] = list(report.instructions)
    return document, report


def _doctor(options: dict[str, Any], io: CliIo) -> int:
    engine, report = _engine_document(options)
    entry = (
        pinned_gateway_policy_for(options["origin"], allow_candidate=True)
        if options["origin"]
        else None
    )
    pin = (
        {
            "present": True,
            "status": entry.status,
            "reviewedAt": entry.reviewed_at,
            "source": entry.policy.source,
            "version": entry.policy.version,
            "requiresOptIn": entry.status == "candidate",
            "requireHardwareVerified": entry.policy.require_hardware_verified,
        }
        if entry is not None
        else {
            "present": False,
            "status": None,
            "reviewedAt": None,
            "source": None,
            "version": None,
            "requiresOptIn": False,
            "requireHardwareVerified": None,
        }
    )
    document = {
        "schema": SCHEMA,
        "command": "doctor",
        "origin": options["origin"],
        "engine": engine,
        "pin": pin,
        "notes": [
            "A DCAP engine is available; hardware_verified is reachable with --dcap."
            if report.available
            else (
                "No DCAP engine found. Verification is capped at "
                "cryptographically_checked and a policy requiring hardware "
                "verification fails closed."
            ),
            *report.instructions,
        ],
    }
    io.out(f'{_serialize(document, options["compact"])}\n')
    # doctor reports; it does not gate. A missing engine is information, not a
    # failed check, so it exits 0 unless the command itself was wrong.
    return EXIT_MET


def _serialize(document: dict[str, Any], compact: bool) -> str:
    """The exact bytes printed. Separators are pinned so the JS twin matches."""
    if compact:
        return json.dumps(document, separators=(",", ":"))
    return json.dumps(document, indent=2)


class CliIo:
    """Where the command writes. Injectable so a test can read what it printed."""

    def __init__(self, out: Any = None, err: Any = None) -> None:
        self.out = out or sys.stdout.write
        self.err = err or sys.stderr.write


def run_cli(argv: list[str], io: CliIo | None = None) -> int:
    """Run one invocation and return its exit code.

    Never raises for a verification outcome: a failure is a document plus a
    nonzero code, because a command that crashed and a command that established
    nothing look identical to a shell otherwise.
    """
    sink = io or CliIo()
    try:
        options = parse_args(list(argv))
    except UsageError as exc:
        sink.err(f"{exc}\n\n{USAGE}" if str(exc) else USAGE)
        return EXIT_USAGE

    try:
        if options["command"] == "doctor":
            return _doctor(options, sink)
        return _verify(options, sink)
    except UsageError as exc:
        sink.err(f"{exc}\n")
        return EXIT_USAGE


def main(argv: list[str] | None = None) -> int:
    """The console-script entry point."""
    return run_cli(list(sys.argv[1:] if argv is None else argv))


def _verify(options: dict[str, Any], io: CliIo) -> int:
    notes: list[str] = []
    engine, report = _engine_document(options)
    origin = options["origin"]
    timeout_seconds = float(options["timeout_ms"]) / 1000.0

    policy, note = _resolve_policy(options)
    notes.append(note)

    collateral = None
    if options["collateral_file"]:
        collateral = _read_json_file(options["collateral_file"], "collateral")
        notes.append(
            f"collateral loaded from {options['collateral_file']}, and it is still "
            "revalidated by the engine"
        )

    chain_verifier = None
    if options["dcap"]:
        chain_verifier = create_anonrouter_dcap_verifier(
            binary_path=options["dcap_binary"],
            expected_binary_sha256=options["dcap_sha256"],
            collateral=collateral,
            fetch_collateral=bool(options["fetch_collateral"]),
            timeout_seconds=timeout_seconds,
        )
        if not report.available:
            notes.append(
                "--dcap was requested but no engine could be resolved, so the chain "
                "check will fail closed"
            )

    observed_spki: str | None = None
    if options["tls_check"]:
        observed_spki = observe_tls_spki(origin, timeout_seconds)
        if observed_spki is None:
            notes.append(
                "this origin's TLS certificate could not be observed, so the "
                "certificate binding is recorded as an unmet gap rather than assumed"
            )
    else:
        notes.append("--no-tls-check was given, so the certificate binding was not established")

    # A key is only needed for hop 2, and it is only ever read from the environment.
    api_key = os.environ.get(options["api_key_env"])
    if options["command"] == "route" and not api_key:
        io.err(
            f"route needs an API key for hop 2. Set {options['api_key_env']}, or name a "
            "different variable with --api-key-env.\n"
            "Hop 1 needs no credential at all: run `anonrouter-verify gateway` instead "
            "if that is what you meant.\n"
        )
        return EXIT_USAGE

    gateway_kwargs: dict[str, Any] = {
        "allow_candidate_policy": bool(options["allow_candidate"]),
    }
    if policy is not None:
        gateway_kwargs["policy"] = policy
    if options["tls_check"]:
        gateway_kwargs["observed_tls_spki_sha256"] = observed_spki
        gateway_kwargs["observed_tls_spki_supplied"] = observed_spki is not None
    if chain_verifier is not None:
        gateway_kwargs["chain_verifier"] = chain_verifier

    # `gateway` is CREDENTIAL-FREE, and that is enforced structurally rather than
    # promised: hop 2 is never attempted, and the only request made is the
    # unauthenticated attestation fetch. Running the full route here would mint an
    # attestation ticket with the real key against an origin the operator has not
    # verified yet, which inverts the trust order this command exists to keep.
    client = create_client(origin, api_key or None, timeout=timeout_seconds)
    try:
        hop1 = client.verify_gateway(**gateway_kwargs)
        gateway_hop = gateway_hop_verdict(hop1["verdict"])

        provider_hop = hop_not_requested()
        attestation: dict[str, Any] | None = None
        if options["command"] == "route":
            try:
                attestation = client.verify_attestation(
                    options["model"],
                    options["provider"],
                    upstream_model=options["upstream_model"],
                )
                provider_hop = provider_hop_verdict(attestation["verdict"])
            except ConfidentialError as exc:
                reason = str(exc) or "provider_verification_failed"
                provider_hop = RouteHopVerdict(
                    requested=True,
                    state="untrusted",
                    meaning=describe_state("untrusted"),
                    reason=reason,
                    failed_checks=[reason],
                )

        verdict = assemble_route_verdict(
            route=RequestedRoute(
                provider=options["provider"] or "-",
                model=options["model"] or "-",
                privacy_modality=(attestation or {}).get("privacy_modality", "e2ee"),
            ),
            gateway=gateway_hop,
            provider=provider_hop,
            gateway_echo=(
                {
                    "provider": attestation.get("provider"),
                    "privacy_class": attestation.get("privacy_modality"),
                }
                if attestation
                else None
            ),
            attested_upstream_model=(attestation or {}).get("upstream_model"),
            expected_upstream_model=options["upstream_model"],
        )

        # On `gateway` the caller asked about the plane, so the plane decides the
        # exit code. On `route` the whole route does, and any binding mismatch
        # overrides both hops however strong they were.
        gated = verdict.gateway.state if options["command"] == "gateway" else verdict.overall_state
        met = at_least(gated, options["require"]) and not verdict.binding_mismatches

        binding = hop1["verdict"].binding
        attested_spki = binding.tls_spki_sha256 if binding else None
        document = {
            "schema": SCHEMA,
            "command": options["command"],
            "origin": origin,
            "requested": {
                "assurance": options["require"],
                "gateway": True,
                "provider": options["provider"] if options["command"] == "route" else None,
                "model": options["model"] if options["command"] == "route" else None,
            },
            "outcome": {
                "met": met,
                "state": gated,
                "reason": None
                if met
                else (
                    (verdict.gateway.reason if options["command"] == "gateway" else verdict.reason)
                    or f"assurance {gated} is below the required {options['require']}"
                ),
            },
            "gateway": {
                **_hop_document(verdict.gateway),
                "policy": hop1["policy"],
                "identity": {
                    "appId": binding.app_id,
                    "instanceId": binding.instance_id,
                    "composeHash": binding.compose_hash,
                    "releaseId": binding.release_id,
                    "origin": binding.origin,
                    "transport": binding.transport,
                    "attestedTlsSpkiSha256": binding.tls_spki_sha256,
                }
                if binding
                else None,
                "measurements": hop1["verdict"].measurements,
                "tcbStatus": hop1["verdict"].tcb_status,
                "tlsSpki": {
                    "observed": observed_spki,
                    "source": "separate-tls-connection" if options["tls_check"] else "not-observed",
                    "matchesAttested": (
                        observed_spki.lower() == str(attested_spki).lower()
                        if observed_spki is not None and attested_spki
                        else None
                    ),
                },
            },
            "provider": _hop_document(verdict.provider),
            "bindingMismatches": [m.as_dict() for m in verdict.binding_mismatches],
            "contentVisibleToAnonRouter": (
                verdict.content_visible_to_anonrouter if options["command"] == "route" else None
            ),
            "engine": engine,
            "notes": notes,
        }
        io.out(f'{_serialize(document, options["compact"])}\n')
        return EXIT_MET if met else EXIT_NOT_MET
    except ConfidentialError as exc:
        document = {
            "schema": SCHEMA,
            "command": options["command"],
            "origin": origin,
            "requested": {
                "assurance": options["require"],
                "gateway": True,
                "provider": options["provider"],
                "model": options["model"],
            },
            "outcome": {"met": False, "state": "unavailable", "reason": str(exc)},
            "gateway": {
                "requested": True,
                "state": "unavailable",
                "meaning": "",
                "reason": str(exc),
                "failedChecks": [],
                "advisoryGaps": [],
            },
            "provider": {
                "requested": options["command"] == "route",
                "state": "unavailable",
                "meaning": "",
                "reason": None,
                "failedChecks": [],
                "advisoryGaps": [],
            },
            "bindingMismatches": [],
            "contentVisibleToAnonRouter": None,
            "engine": engine,
            "notes": notes,
        }
        io.out(f'{_serialize(document, options["compact"])}\n')
        return EXIT_NOT_MET
    finally:
        client.close()


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
