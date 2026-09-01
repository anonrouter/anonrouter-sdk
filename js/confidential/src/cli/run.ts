// anonrouter-verify: check a route from a terminal, and exit nonzero unless the
// assurance you asked for was actually established.
//
// This exists so verification can gate something. A library call that returns a
// verdict is useful inside an application; a command that fails a shell is what
// you put in front of a deploy, a health check, or a CI job that must not proceed
// against an unverified plane.
//
//   anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap \
//     --require hardware_verified --policy ./reviewed-policy.json
//   echo $?    # 0 met, 1 not met, 2 the command itself was wrong
//
// WHAT IT PRINTS. One JSON document on stdout, always, including on failure, so a
// caller can branch on the exit code and still read why. Diagnostics go to stderr.
//
// WHAT IT NEVER PRINTS. No API key, no ticket, no prompt or response content, and
// no raw evidence body. The gateway document carries ~66 KB of internal compose
// topology; the identity and measurements that matter are extracted, and the rest
// is deliberately dropped rather than dumped into somebody's CI log. An API key is
// read from an environment variable and never accepted on argv, where it would be
// visible in the process table and in shell history.

import { readFileSync } from "node:fs";
import { connect as tlsConnect } from "node:tls";
import { createHash } from "node:crypto";
import { createClient, type VerifyGatewayInput } from "../client.js";
import { ConfidentialError } from "../errors.js";
import { loadGatewayPolicy, pinnedGatewayPolicyFor, type GatewayMeasurementPolicy } from "../gateway/policy.js";
import { createAnonRouterDcapVerifier, describeDcapInstallation } from "../gateway/dcap/index.js";
import type { DcapCollateral } from "../gateway/dcap/collateral.js";
import { atLeast, describeState, TRUSTED_STATES, type RouteVerificationState } from "../verify/state.js";
import {
  assembleRouteVerdict,
  gatewayHopVerdict,
  hopNotRequested,
  hopUnavailable,
  providerHopVerdict,
  type RouteHopVerdict
} from "../verify/route.js";

/** The output contract. Bumped only when the document's shape changes. */
export const SCHEMA = "anonrouter-verify/1";

export const EXIT_MET = 0;
export const EXIT_NOT_MET = 1;
export const EXIT_USAGE = 2;

export const USAGE = `anonrouter-verify: independently verify an AnonRouter route.

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
  --control-origin <url>    Identity/billing origin for content-free ticket
                            operations. Production content names default to
                            https://control.anonrouter.ai; custom names use --origin.
  --require <state>         Minimum assurance to exit 0. One of:
                            ${TRUSTED_STATES.join(", ")}.
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
`;

export interface Options {
  command: "gateway" | "route" | "doctor";
  origin: string | null;
  controlOrigin: string | null;
  require: RouteVerificationState;
  policyFile: string | null;
  allowCandidate: boolean;
  dcap: boolean;
  dcapBinary: string | null;
  dcapSha256: string | null;
  collateralFile: string | null;
  fetchCollateral: boolean;
  tlsCheck: boolean;
  apiKeyEnv: string;
  timeoutMs: number;
  compact: boolean;
  provider: string | null;
  model: string | null;
  upstreamModel: string | null;
}

export class UsageError extends Error {}

export function parseArgs(argv: string[]): Options {
  const options: Options = {
    command: "doctor",
    origin: null,
    controlOrigin: null,
    require: "cryptographically_checked",
    policyFile: null,
    allowCandidate: false,
    dcap: false,
    dcapBinary: null,
    dcapSha256: null,
    collateralFile: null,
    fetchCollateral: true,
    tlsCheck: true,
    apiKeyEnv: "ANONROUTER_API_KEY",
    timeoutMs: 30_000,
    compact: false,
    provider: null,
    model: null,
    upstreamModel: null
  };

  const [first, ...rest] = argv;
  if (first === undefined || first === "-h" || first === "--help") {
    throw new UsageError("");
  }
  if (first !== "gateway" && first !== "route" && first !== "doctor") {
    throw new UsageError(`unknown command "${first}"`);
  }
  options.command = first;

  const value = (index: number, flag: string): string => {
    const next = rest[index + 1];
    if (next === undefined || next.startsWith("--")) throw new UsageError(`${flag} needs a value`);
    return next;
  };

  for (let i = 0; i < rest.length; i += 1) {
    const flag = rest[i];
    switch (flag) {
      case "-h": case "--help": throw new UsageError("");
      case "--origin": options.origin = value(i, flag); i += 1; break;
      case "--control-origin": options.controlOrigin = value(i, flag); i += 1; break;
      case "--require": options.require = value(i, flag) as RouteVerificationState; i += 1; break;
      case "--policy": options.policyFile = value(i, flag); i += 1; break;
      case "--allow-candidate": options.allowCandidate = true; break;
      case "--dcap": options.dcap = true; break;
      case "--dcap-binary": options.dcapBinary = value(i, flag); options.dcap = true; i += 1; break;
      case "--dcap-sha256": options.dcapSha256 = value(i, flag); i += 1; break;
      case "--collateral": options.collateralFile = value(i, flag); i += 1; break;
      case "--no-collateral-fetch": options.fetchCollateral = false; break;
      case "--no-tls-check": options.tlsCheck = false; break;
      case "--api-key-env": options.apiKeyEnv = value(i, flag); i += 1; break;
      case "--timeout": options.timeoutMs = Number(value(i, flag)); i += 1; break;
      case "--compact": options.compact = true; break;
      case "--provider": options.provider = value(i, flag); i += 1; break;
      case "--model": options.model = value(i, flag); i += 1; break;
      case "--upstream-model": options.upstreamModel = value(i, flag); i += 1; break;
      default:
        // An API key on argv is visible in the process table and in shell
        // history, so it is refused by name rather than silently ignored.
        if (flag === "--api-key") {
          throw new UsageError("--api-key is refused: pass the key through an environment variable and name it with --api-key-env");
        }
        throw new UsageError(`unknown option "${flag}"`);
    }
  }

  if (!TRUSTED_STATES.includes(options.require)) {
    throw new UsageError(`--require must be one of ${TRUSTED_STATES.join(", ")}`);
  }
  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new UsageError("--timeout must be a positive number of milliseconds");
  }
  if (options.command !== "doctor" && !options.origin) {
    throw new UsageError(`${options.command} needs --origin`);
  }
  if (options.command === "route" && (!options.provider || !options.model)) {
    throw new UsageError("route needs --provider and --model");
  }
  if (options.require === "hardware_verified" && !options.dcap && options.command !== "doctor") {
    // Better to refuse the command than to run it and report a failure whose
    // cause is that the operator did not ask for the thing they required.
    throw new UsageError("--require hardware_verified needs --dcap: without a chain verifier nothing can reach that state");
  }
  if (!options.fetchCollateral && !options.collateralFile) {
    throw new UsageError("--no-collateral-fetch needs --collateral <file>");
  }
  return options;
}

function readJsonFile(path: string, what: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new UsageError(`could not read ${what} from ${path}: ${error instanceof Error ? error.message : "unreadable"}`);
  }
}

/**
 * Observe the leaf certificate's SPKI on this origin.
 *
 * HONESTY NOTE, carried into the output as `source`: this opens its own TLS
 * connection rather than reading the certificate off the connection that carried
 * the attestation request, because fetch does not expose it. Against a single
 * origin terminating TLS inside one TD those are the same certificate, and a
 * mismatch is still conclusive. Against a fleet presenting different keys per
 * connection, agreement is weaker than a same-connection observation would be.
 */
async function observeTlsSpki(origin: string, timeoutMs: number): Promise<string | null> {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: string | null) => {
      if (!settled) { settled = true; resolve(value); }
    };
    const socket = tlsConnect(
      {
        host: url.hostname,
        port: url.port ? Number(url.port) : 443,
        servername: url.hostname,
        // The public chain must validate on its own. A CLI that disabled this
        // would be observing a certificate nobody vouched for.
        rejectUnauthorized: true
      },
      () => {
        try {
          const certificate = socket.getPeerX509Certificate();
          if (!certificate) return done(null);
          const der = certificate.publicKey.export({ type: "spki", format: "der" });
          done(createHash("sha256").update(der).digest("hex"));
        } catch {
          done(null);
        } finally {
          socket.destroy();
        }
      }
    );
    socket.setTimeout(timeoutMs, () => { socket.destroy(); done(null); });
    socket.on("error", () => { socket.destroy(); done(null); });
  });
}

/** Project a hop verdict into the output document. Never carries raw evidence. */
function hopDocument(hop: RouteHopVerdict): Record<string, unknown> {
  return {
    requested: hop.requested,
    state: hop.state,
    meaning: hop.meaning,
    reason: hop.reason,
    failedChecks: hop.failedChecks,
    advisoryGaps: hop.advisoryGaps
  };
}

function resolvePolicy(options: Options): { policy?: GatewayMeasurementPolicy; note: string } {
  if (options.policyFile) {
    const raw = readJsonFile(options.policyFile, "policy");
    // Accept either a bare policy or a registry entry wrapping one, because both
    // shapes exist in the wild and guessing wrong is a confusing parse error.
    const candidate = raw && typeof raw === "object" && "policy" in (raw as Record<string, unknown>)
      ? (raw as Record<string, unknown>).policy
      : raw;
    try {
      return { policy: loadGatewayPolicy(candidate), note: `policy loaded from ${options.policyFile}` };
    } catch (error) {
      throw new UsageError(`policy at ${options.policyFile} is not valid: ${error instanceof Error ? error.message : "unparseable"}`);
    }
  }
  return { note: "using the pin this package ships for the origin" };
}

/** Where the command writes. Injectable so a test can read what it printed. */
export interface CliIo {
  out(text: string): void;
  err(text: string): void;
}

const PROCESS_IO: CliIo = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text)
};

/**
 * Run one invocation and return its exit code.
 *
 * Never throws for a verification outcome: a failure is a document plus a
 * nonzero code, because a command that crashed and a command that established
 * nothing look identical to a shell otherwise.
 */
export async function runCli(argv: string[], io: CliIo = PROCESS_IO): Promise<number> {
  let options: Options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      io.err(error.message ? `${error.message}\n\n${USAGE}` : USAGE);
      return error.message ? EXIT_USAGE : EXIT_USAGE;
    }
    throw error;
  }

  try {
    return await runResolved(options, io);
  } catch (error) {
    // A bad --policy or --collateral file is the command's inputs being wrong,
    // which is exit 2 with the usage text, not a verification answer.
    if (error instanceof UsageError) {
      io.err(`${error.message}\n`);
      return EXIT_USAGE;
    }
    throw error;
  }
}

async function runResolved(options: Options, io: CliIo): Promise<number> {
  const notes: string[] = [];
  const engineReport = describeDcapInstallation({ binaryPath: options.dcapBinary ?? undefined });
  const engine = {
    requested: options.dcap,
    available: engineReport.available,
    binaryPath: engineReport.binaryPath,
    binarySha256: engineReport.binarySha256,
    origin: engineReport.origin,
    target: engineReport.target,
    reason: engineReport.reason,
    ...(options.dcap && !engineReport.available ? { instructions: engineReport.instructions } : {})
  };

  if (options.command === "doctor") {
    const pinned = options.origin
      ? pinnedGatewayPolicyFor(options.origin, { allowCandidate: true })
      : undefined;
    const document = {
      schema: SCHEMA,
      command: "doctor",
      origin: options.origin,
      engine,
      pin: pinned
        ? {
          present: true,
          status: pinned.status,
          reviewedAt: pinned.reviewedAt,
          source: pinned.policy.source,
          version: pinned.policy.version,
          requiresOptIn: pinned.status === "candidate",
          requireHardwareVerified: pinned.policy.requireHardwareVerified
        }
        : { present: false, status: null, reviewedAt: null, source: null, version: null, requiresOptIn: false, requireHardwareVerified: null },
      notes: [
        engineReport.available
          ? "A DCAP engine is available; hardware_verified is reachable with --dcap."
          : "No DCAP engine found. Verification is capped at cryptographically_checked and a policy requiring hardware verification fails closed.",
        ...engineReport.instructions
      ]
    };
    io.out(`${JSON.stringify(document, null, options.compact ? 0 : 2)}\n`);
    // doctor reports; it does not gate. A missing engine is information, not a
    // failed check, so it exits 0 unless the command itself was wrong.
    return EXIT_MET;
  }

  const origin = options.origin!;
  const { policy, note } = resolvePolicy(options);
  notes.push(note);

  let collateral: DcapCollateral | undefined;
  if (options.collateralFile) {
    collateral = readJsonFile(options.collateralFile, "collateral") as DcapCollateral;
    notes.push(`collateral loaded from ${options.collateralFile}, and it is still revalidated by the engine`);
  }

  const chainVerifier = options.dcap
    ? createAnonRouterDcapVerifier({
      ...(options.dcapBinary ? { binaryPath: options.dcapBinary } : {}),
      ...(options.dcapSha256 ? { expectedBinarySha256: options.dcapSha256 } : {}),
      ...(collateral ? { collateral } : {}),
      fetchCollateral: options.fetchCollateral,
      timeoutMs: options.timeoutMs
    })
    : undefined;
  if (options.dcap && !engineReport.available) {
    notes.push("--dcap was requested but no engine could be resolved, so the chain check will fail closed");
  }

  let observedSpki: string | null = null;
  if (options.tlsCheck) {
    observedSpki = await observeTlsSpki(origin, options.timeoutMs);
    if (observedSpki === null) {
      notes.push("this origin's TLS certificate could not be observed, so the certificate binding is recorded as an unmet gap rather than assumed");
    }
  } else {
    notes.push("--no-tls-check was given, so the certificate binding was not established");
  }

  const gatewayOption: Omit<VerifyGatewayInput, "signal"> = {
    ...(policy ? { policy } : {}),
    allowCandidatePolicy: options.allowCandidate,
    // Only when an observation actually succeeded. Passing null would mean
    // "observed, and there is no certificate", which is a MISMATCH and a required
    // failure; a handshake this command could not complete is a gap, recorded as
    // advisory and called out in `notes`. The Python command does the same, and
    // getting this wrong would make the two disagree about a live origin while
    // agreeing on every offline case the parity gate can reach.
    ...(options.tlsCheck && observedSpki !== null ? { observedTlsSpkiSha256: observedSpki } : {}),
    ...(chainVerifier ? { chainVerifier } : {})
  };

  // A key is only needed for hop 2, and it is only ever read from the environment.
  const apiKey = process.env[options.apiKeyEnv];
  if (options.command === "route" && (!apiKey || apiKey.length === 0)) {
    io.err(
      `route needs an API key for hop 2. Set ${options.apiKeyEnv}, or name a different variable with --api-key-env.\n`
      + "Hop 1 needs no credential at all: run `anonrouter-verify gateway` instead if that is what you meant.\n"
    );
    return EXIT_USAGE;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    // `gateway` is CREDENTIAL-FREE, and that is enforced structurally rather than
    // promised: the client is constructed with a placeholder, hop 2 is never
    // attempted, and the only request made is the unauthenticated attestation
    // fetch. Running verifyRoute here would mint an attestation ticket with the
    // real key against an origin the operator has not verified yet, which inverts
    // the trust order this whole command exists to keep.
    const client = createClient({
      baseUrl: origin,
      ...(options.controlOrigin ? { controlBaseUrl: options.controlOrigin } : {}),
      apiKey: apiKey && apiKey.length > 0 ? apiKey : "unused-for-gateway-verification"
    });

    // Hop 1 not being ATTEMPTABLE (no pin for this origin, no attestation route
    // here) must not stop hop 2 from being reported. They are separate questions,
    // and a caller who asked about the route deserves the answer to the half that
    // could be established. It still cannot prop the verdict up: an unavailable
    // hop is not a passing hop, and assembleRouteVerdict takes the weakest.
    let hop1: Awaited<ReturnType<typeof client.verifyGateway>> | null = null;
    let gatewayHop;
    try {
      hop1 = await client.verifyGateway({ ...gatewayOption, signal: controller.signal });
      gatewayHop = gatewayHopVerdict(hop1.verdict);
    } catch (error) {
      if (error instanceof ConfidentialError && error.code === "cancelled") throw error;
      gatewayHop = hopUnavailable(error instanceof Error ? error.message : "gateway verification could not be attempted");
    }

    let providerHop = hopNotRequested();
    let attestation: Awaited<ReturnType<typeof client.verifyAttestation>> | null = null;
    if (options.command === "route") {
      try {
        attestation = await client.verifyAttestation({
          model: options.model!,
          provider: options.provider!,
          ...(options.upstreamModel ? { upstreamModel: options.upstreamModel } : {}),
          signal: controller.signal
        });
        providerHop = providerHopVerdict(attestation.verdict);
      } catch (error) {
        // The CODE is the stable machine-readable name and the MESSAGE says what
        // to do about it. Reporting only the code turns "your key was refused"
        // and "this origin does not serve the route" into the same word.
        const providerError = error instanceof ConfidentialError ? error.code : "provider_verification_failed";
        providerHop = {
          requested: true,
          state: "untrusted",
          meaning: describeState("untrusted"),
          reason: error instanceof Error ? error.message : providerError,
          failedChecks: [providerError],
          advisoryGaps: []
        };
      }
    }

    const verdict = assembleRouteVerdict({
      route: {
        provider: options.provider ?? "-",
        model: options.model ?? "-",
        privacyModality: attestation?.privacyModality ?? "e2ee"
      },
      gateway: gatewayHop,
      provider: providerHop,
      ...(attestation
        ? {
          gatewayEcho: { provider: attestation.provider, privacyClass: attestation.privacyModality },
          attestedUpstreamModel: attestation.upstreamModel
        }
        : {}),
      expectedUpstreamModel: options.upstreamModel ?? null
    });

    // On `gateway` the caller asked about the plane, so the plane decides the
    // exit code. On `route` the whole route does, and any binding mismatch
    // overrides both hops however strong they were.
    const gated = options.command === "gateway" ? verdict.gateway.state : verdict.overallState;
    const met = atLeast(gated, options.require) && verdict.bindingMismatches.length === 0;

    const binding = hop1?.verdict.binding ?? null;
    const document = {
      schema: SCHEMA,
      command: options.command,
      origin,
      requested: {
        assurance: options.require,
        gateway: true,
        provider: options.command === "route" ? options.provider : null,
        model: options.command === "route" ? options.model : null
      },
      outcome: {
        met,
        state: gated,
        reason: met
          ? null
          : (options.command === "gateway" ? verdict.gateway.reason : verdict.reason)
          ?? `assurance ${gated} is below the required ${options.require}`
      },
      gateway: {
        ...hopDocument(verdict.gateway),
        policy: hop1?.policy ?? null,
        identity: binding
          ? {
            appId: binding.app_id,
            instanceId: binding.instance_id,
            composeHash: binding.compose_hash,
            releaseId: binding.release_id,
            origin: binding.origin,
            transport: binding.transport,
            attestedTlsSpkiSha256: binding.tls_spki_sha256
          }
          : null,
        measurements: hop1?.verdict.measurements ?? null,
        tcbStatus: hop1?.verdict.tcbStatus ?? null,
        tlsSpki: {
          observed: observedSpki,
          source: options.tlsCheck ? "separate-tls-connection" : "not-observed",
          matchesAttested: observedSpki !== null && binding?.tls_spki_sha256
            ? observedSpki.toLowerCase() === String(binding.tls_spki_sha256).toLowerCase()
            : null
        }
      },
      provider: hopDocument(verdict.provider),
      bindingMismatches: verdict.bindingMismatches,
      contentVisibleToAnonRouter: options.command === "route" ? verdict.contentVisibleToAnonRouter : null,
      engine,
      notes
    };
    io.out(`${JSON.stringify(document, null, options.compact ? 0 : 2)}\n`);
    return met ? EXIT_MET : EXIT_NOT_MET;
  } catch (error) {
    const code = error instanceof ConfidentialError ? error.code : "verification_failed";
    const message = error instanceof Error ? error.message : "verification failed";
    const document = {
      schema: SCHEMA,
      command: options.command,
      origin,
      requested: { assurance: options.require, gateway: true, provider: options.provider, model: options.model },
      outcome: { met: false, state: "unavailable", reason: `${code}: ${message}` },
      gateway: { requested: true, state: "unavailable", meaning: "", reason: message, failedChecks: [], advisoryGaps: [] },
      provider: { requested: options.command === "route", state: "unavailable", meaning: "", reason: null, failedChecks: [], advisoryGaps: [] },
      bindingMismatches: [],
      contentVisibleToAnonRouter: null,
      engine,
      notes
    };
    io.out(`${JSON.stringify(document, null, options.compact ? 0 : 2)}\n`);
    return EXIT_NOT_MET;
  } finally {
    clearTimeout(timer);
  }
}
