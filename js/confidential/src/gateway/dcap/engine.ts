// The official DCAP chain-verifier adapter. NODE ONLY.
//
// This is the answer to "how does an ordinary user reach hardware_verified?".
// It drives AnonRouter's reviewed offline DCAP engine (`anonrouter-dcap-verifier`,
// dcap-qvl 0.6.1, no network, pinned Intel root, explicit TCB gate) across a
// process boundary, and it is the only adapter in this package that speaks that
// engine's exact wire contract.
//
// WHY NO ENGINE IS BUNDLED, STATED PLAINLY
//
// A real DCAP verifier is native code. Shipping one inside an npm tarball would
// mean publishing prebuilt binaries for every platform, and this package cannot
// honestly assert that a binary it did not build reproducibly is the reviewed
// engine. A hand-rolled JavaScript reimplementation would be worse: it would be
// an unreviewed, un-cross-checked implementation of the one component whose
// failure mode is "prints hardware_verified for a forged quote". So the engine
// stays a separate, reviewed artifact you install, and this module is a strict,
// fail-closed adapter to it. `describeDcapInstallation()` tells a user exactly
// what to install and where this module will look.
//
// THE WIRE CONTRACT (engine request v1)
//
//   stdin   {"v":1,"quote":"<hex>","collateral":{...},"now_secs":N,
//            "accepted_tcb_statuses":["UpToDate"]}
//   stdout  {"v":1,"verified":bool,"tcb_status":"...","qe_tcb_status":"...",
//            "platform_tcb_status":"...","advisory_ids":[],"report":{...},
//            "error":null,"engine":"anonrouter-dcap-verifier/x dcap-qvl/y"}
//   exit    0 verified, 1 not verified, 2 unusable input
//
// The exit code is NOT the answer: the engine prints a verdict for both 0 and 1.
// The verdict is parsed first and `verified` must be exactly `true`.
//
// FAIL CLOSED, ALWAYS. A missing binary, a digest that does not match the pin, a
// timeout, a crash, a non-zero exit with no verdict, output that is not JSON,
// output that is too large, a `verified` field that is not a real boolean,
// collateral that could not be acquired, or an engine report that disagrees with
// the quote we parsed all resolve to not-verified. Nothing here throws into the
// verifier, and there is no path where an error becomes a pass.

import { execFile } from "node:child_process";
import { accessSync, constants, readFileSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "../../bytes.js";
import { parseTdxQuote } from "../../verify/tdx.js";
import type { TdxChainVerifier, TdxChainVerifierFactory, TdxChainVerifierContext } from "../verify.js";
import {
  CollateralCache,
  fetchIntelCollateral,
  normalizeQuoteHex,
  type DcapCollateral
} from "./collateral.js";

/** The program name the engine is published under. */
export const DCAP_ENGINE_PROGRAM = "anonrouter-dcap-verifier";
/** The environment variable an operator sets to point at an installed engine. */
export const DCAP_ENGINE_ENV = "ANONROUTER_DCAP_VERIFIER_BIN";
/** The request wire version this adapter speaks. */
export const DCAP_ENGINE_REQUEST_VERSION = 1;

/** A verdict is small; anything larger means something is wrong. */
const MAX_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;

/** The measured fields the engine echoes, so a caller need not re-parse the quote. */
export interface DcapTdReport {
  kind: string;
  tee_tcb_svn: string;
  mr_seam: string;
  mr_signer_seam: string;
  td_attributes: string;
  xfam: string;
  mr_td: string;
  mr_config_id: string;
  mr_owner: string;
  mr_owner_config: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  report_data: string;
  debug: boolean;
}

/** The engine's v1 verdict, normalized. Every optional field becomes explicit. */
export interface DcapEngineVerdictV1 {
  verified: boolean;
  tcbStatus: string | null;
  qeTcbStatus: string | null;
  platformTcbStatus: string | null;
  advisoryIds: string[];
  report: DcapTdReport | null;
  /** Content-free reason, present when `verified` is false. */
  error: string | null;
  /** Which engine produced this, for the audit trail. */
  engine: string;
}

export interface DcapEngineRequestV1 {
  v: number;
  quote: string;
  collateral: DcapCollateral;
  now_secs: number;
  accepted_tcb_statuses?: string[];
}

/**
 * Build the exact request document the engine reads on stdin.
 *
 * Exported and pure so the shared known-answer vectors can pin it: if JS and
 * Python ever serialized a different request, they would be verifying different
 * things while reporting the same verdict shape.
 */
export function buildDcapEngineRequest(
  quoteHex: string,
  collateral: DcapCollateral,
  nowSecs: number,
  acceptedTcbStatuses?: readonly string[]
): DcapEngineRequestV1 {
  return {
    v: DCAP_ENGINE_REQUEST_VERSION,
    quote: quoteHex,
    collateral,
    now_secs: Math.floor(nowSecs),
    ...(acceptedTcbStatuses && acceptedTcbStatuses.length > 0
      ? { accepted_tcb_statuses: [...acceptedTcbStatuses] }
      : {})
  };
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/**
 * Parse the engine's stdout into a verdict, or null if it is unusable.
 *
 * `verified` must be a real boolean: a truthy string, a 1, or a missing field is
 * a malformed verdict, and coercing any of them would invent a pass out of noise.
 */
export function parseDcapEngineVerdict(stdout: string): DcapEngineVerdictV1 | null {
  if (typeof stdout !== "string" || stdout.length === 0 || stdout.length > MAX_OUTPUT_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;
  if (typeof record.verified !== "boolean") return null;
  const report = record.report;
  return {
    verified: record.verified,
    tcbStatus: stringOrNull(record.tcb_status),
    qeTcbStatus: stringOrNull(record.qe_tcb_status),
    platformTcbStatus: stringOrNull(record.platform_tcb_status),
    advisoryIds: Array.isArray(record.advisory_ids)
      ? record.advisory_ids.filter((value): value is string => typeof value === "string")
      : [],
    report: report && typeof report === "object" && !Array.isArray(report)
      ? (report as unknown as DcapTdReport)
      : null,
    error: stringOrNull(record.error),
    engine: stringOrNull(record.engine) ?? "unknown"
  };
}

// ---- Locating the engine ------------------------------------------------------

/** Where a resolved engine came from, so an audit trail is never ambiguous. */
export type DcapBinaryOrigin = "explicit" | "environment" | "path" | "none";

export interface ResolvedDcapBinary {
  path: string | null;
  origin: DcapBinaryOrigin;
  /** Why nothing was resolved, when `path` is null. */
  reason: string | null;
}

function isExecutableFile(candidate: string): boolean {
  try {
    accessSync(candidate, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Look up an exact program name on PATH. Never a wildcard or a fuzzy match. */
function findOnPath(program: string): string | null {
  const raw = process.env.PATH;
  if (typeof raw !== "string" || raw.length === 0) return null;
  for (const dir of raw.split(delimiter)) {
    if (dir.length === 0) continue;
    const candidate = join(dir, program);
    if (isExecutableFile(candidate)) return candidate;
  }
  return null;
}

/**
 * Resolve which engine to run.
 *
 * Order: an explicit path, then `ANONROUTER_DCAP_VERIFIER_BIN`, then the exact
 * program name on PATH. All three are choices an operator made.
 *
 * THE LOAD-BEARING RULE: a source that is named but unusable resolves to
 * NOTHING. An explicit path that does not exist does not fall through to the
 * environment, and an environment variable that does not exist does not fall
 * through to PATH. Silently verifying with an engine the caller did not name is
 * exactly the substitution this component exists to prevent.
 */
export function resolveDcapVerifierBinary(
  explicit?: string,
  options: { searchPath?: boolean; env?: NodeJS.ProcessEnv } = {}
): ResolvedDcapBinary {
  const env = options.env ?? process.env;
  if (typeof explicit === "string" && explicit.length > 0) {
    return isExecutableFile(explicit)
      ? { path: explicit, origin: "explicit", reason: null }
      : { path: null, origin: "none", reason: `the requested engine ${explicit} is not an executable file` };
  }
  const fromEnv = env[DCAP_ENGINE_ENV];
  if (typeof fromEnv === "string" && fromEnv.length > 0) {
    return isExecutableFile(fromEnv)
      ? { path: fromEnv, origin: "environment", reason: null }
      : { path: null, origin: "none", reason: `${DCAP_ENGINE_ENV} points at ${fromEnv}, which is not an executable file` };
  }
  if (options.searchPath === false) {
    return { path: null, origin: "none", reason: `no engine given and ${DCAP_ENGINE_ENV} is unset` };
  }
  const onPath = findOnPath(DCAP_ENGINE_PROGRAM);
  return onPath
    ? { path: onPath, origin: "path", reason: null }
    : { path: null, origin: "none", reason: `no ${DCAP_ENGINE_PROGRAM} found: set ${DCAP_ENGINE_ENV} or put it on PATH` };
}

/** SHA-256 of a file, lowercase hex, or null when it cannot be read. */
export function fileSha256(path: string): string | null {
  try {
    return bytesToHex(sha256(new Uint8Array(readFileSync(path))));
  } catch {
    return null;
  }
}

/** The Rust target triple for the current host, or null when it is not one we name. */
export function dcapPlatformTarget(
  platform: string = process.platform,
  arch: string = process.arch
): string | null {
  const key = `${platform}/${arch}`;
  switch (key) {
    case "linux/x64": return "x86_64-unknown-linux-gnu";
    case "linux/arm64": return "aarch64-unknown-linux-gnu";
    case "darwin/x64": return "x86_64-apple-darwin";
    case "darwin/arm64": return "aarch64-apple-darwin";
    case "win32/x64": return "x86_64-pc-windows-msvc";
    default: return null;
  }
}

export interface DcapInstallationReport {
  /** Whether an engine was found. */
  available: boolean;
  binaryPath: string | null;
  origin: DcapBinaryOrigin;
  /** SHA-256 of the resolved engine, so an operator can compare it to a release. */
  binarySha256: string | null;
  /** Rust target triple for this host, or null when this host is not a named target. */
  target: string | null;
  platform: string;
  arch: string;
  /** Why nothing was resolved, or null. */
  reason: string | null;
  /** Exact, content-free instructions. Safe to print. */
  instructions: string[];
}

/**
 * Report whether the engine is installed, and say exactly what to do if not.
 *
 * This is what the `doctor` command prints. It never reads or echoes any
 * credential, and it never guesses: the reported path is the one that would
 * actually be executed.
 */
export function describeDcapInstallation(
  options: { binaryPath?: string; searchPath?: boolean; env?: NodeJS.ProcessEnv } = {}
): DcapInstallationReport {
  const resolved = resolveDcapVerifierBinary(options.binaryPath, {
    searchPath: options.searchPath,
    env: options.env
  });
  const target = dcapPlatformTarget();
  const instructions = resolved.path
    ? [
      `Engine resolved from ${resolved.origin}: ${resolved.path}`,
      "Compare its SHA-256 against the digest published with the release you intend to run.",
      `Pin it in code with expectedBinarySha256 so a swapped binary fails closed.`
    ]
    : [
      `This package bundles no DCAP engine, by design: it cannot honestly assert that a binary it did not build reproducibly is the reviewed one.`,
      `Install the ${DCAP_ENGINE_PROGRAM} release artifact for ${target ?? `${process.platform}/${process.arch} (not a named target)`}.`,
      `Then either put it on PATH under the name ${DCAP_ENGINE_PROGRAM}, or set ${DCAP_ENGINE_ENV} to its absolute path, or pass binaryPath explicitly.`,
      `Verify the artifact's SHA-256 against the digest published alongside it, obtained independently of the gateway you are verifying.`,
      `Without an engine, verification is capped at cryptographically_checked and a policy requiring hardware verification fails closed. It never silently downgrades.`
    ];
  return {
    available: resolved.path !== null,
    binaryPath: resolved.path,
    origin: resolved.origin,
    binarySha256: resolved.path ? fileSha256(resolved.path) : null,
    target,
    platform: process.platform,
    arch: process.arch,
    reason: resolved.reason,
    instructions
  };
}

// ---- Running the engine -------------------------------------------------------

/** Run the engine once over a fully-formed request. Never throws. */
export async function runDcapEngine(
  binaryPath: string,
  request: DcapEngineRequestV1,
  timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<DcapEngineVerdictV1> {
  const payload = JSON.stringify(request);
  const outcome = await new Promise<{ stdout: string; failure: string | null }>((resolve) => {
    let settled = false;
    const done = (value: { stdout: string; failure: string | null }) => {
      if (!settled) { settled = true; resolve(value); }
    };
    let child;
    try {
      // execFile, not exec: no shell, so nothing in the request can be
      // interpreted as a command. The request travels on stdin, never argv, so a
      // quote never appears in the process table.
      child = execFile(
        binaryPath,
        [],
        { timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES, encoding: "utf8" },
        (error, stdout) => done({
          stdout: String(stdout ?? ""),
          failure: error ? String(error.code ?? "error") : null
        })
      );
    } catch {
      done({ stdout: "", failure: "spawn" });
      return;
    }
    child.on("error", () => done({ stdout: "", failure: "spawn" }));
    child.stdin?.on("error", () => {
      /* the child may exit before the write drains; the callback reports it */
    });
    try {
      child.stdin?.end(payload);
    } catch {
      done({ stdout: "", failure: "stdin" });
    }
  });

  // A non-zero exit is EXPECTED for "not verified", and the engine still prints
  // a verdict, so the exit code is not the answer. Parse first.
  const verdict = parseDcapEngineVerdict(outcome.stdout.trim());
  if (verdict) return verdict;
  return {
    verified: false,
    tcbStatus: null,
    qeTcbStatus: null,
    platformTcbStatus: null,
    advisoryIds: [],
    report: null,
    error: outcome.failure
      ? `engine produced no usable verdict (${outcome.failure})`
      : "engine produced no usable verdict",
    engine: "unavailable"
  };
}

/**
 * Cross-check the engine's own view of the TD against the quote we parsed.
 *
 * The engine and this SDK read the same bytes independently. If they disagree
 * about mr_td, the RTMRs, or report_data, then one of them is not looking at the
 * quote the caller is about to trust, and the only safe reading of that is
 * refusal. Returns a content-free reason, or null when they agree.
 */
export function engineReportDisagreement(quoteHex: string, report: DcapTdReport | null): string | null {
  if (!report) return null;
  const parsed = parseTdxQuote(quoteHex);
  if (!parsed) return "the SDK could not parse the quote the engine verified";
  const same = (a: unknown, b: string) => typeof a === "string" && a.toLowerCase() === b.toLowerCase();
  if (!same(report.mr_td, parsed.mrTd)) return "engine and SDK disagree about mr_td";
  if (!same(report.mr_config_id, parsed.mrConfigId)) return "engine and SDK disagree about mr_config_id";
  if (!same(report.rtmr0, parsed.rtmr0)) return "engine and SDK disagree about rtmr0";
  if (!same(report.rtmr1, parsed.rtmr1)) return "engine and SDK disagree about rtmr1";
  if (!same(report.rtmr2, parsed.rtmr2)) return "engine and SDK disagree about rtmr2";
  if (!same(report.rtmr3, parsed.rtmr3)) return "engine and SDK disagree about rtmr3";
  if (!same(report.report_data, parsed.reportData)) return "engine and SDK disagree about report_data";
  return null;
}

export interface AnonRouterDcapVerifierOptions {
  /**
   * Path to the engine. Omit to resolve from `ANONROUTER_DCAP_VERIFIER_BIN` and
   * then PATH. A named-but-missing source never falls through to another binary.
   */
  binaryPath?: string;
  /** Refuse to run PATH lookup. Use when only an explicit engine is acceptable. */
  searchPath?: boolean;
  /**
   * Pin the engine's SHA-256. When set, an engine whose digest differs is
   * refused before it runs, so a swapped binary is a failure rather than a
   * different answer. Obtain the digest independently of the gateway.
   */
  expectedBinarySha256?: string;
  /** Hard deadline for the engine process. Real verification is milliseconds. */
  timeoutMs?: number;
  /**
   * Collateral to hand the engine. Supply it to avoid any network access, or
   * omit it to fetch from Intel (see collateral.ts for the privacy note).
   */
  collateral?: DcapCollateral;
  /** Set false to refuse to fetch collateral. Without `collateral`, that is a refusal. */
  fetchCollateral?: boolean;
  /** Reuse a cache across calls so one FMSPC is fetched once per `nextUpdate`. */
  collateralCache?: CollateralCache;
  /** Mirror bases, for an operator who does not want to reach Intel directly. */
  pcsBase?: string;
  certBase?: string;
  fetch?: typeof globalThis.fetch;
  /** Label carried into the verdict. Defaults to the engine's own identity string. */
  implementation?: string;
}

/**
 * The recommended production adapter.
 *
 * Returns a factory: the client prepares it against the exact quote it just
 * fetched, and passes the policy's accepted TCB statuses in, so the engine and
 * the local policy cannot disagree about what "acceptable" means. The prepared
 * verifier answers only for that quote.
 */
export function createAnonRouterDcapVerifier(
  options: AnonRouterDcapVerifierOptions = {}
): TdxChainVerifierFactory {
  const cache = options.collateralCache
    ?? new CollateralCache((quote) => fetchIntelCollateral(quote, {
      pcsBase: options.pcsBase,
      certBase: options.certBase,
      ...(options.fetch ? { fetch: options.fetch as never } : {})
    }));

  return {
    async prepare(quote: string, context: TdxChainVerifierContext = {}): Promise<TdxChainVerifier> {
      const quoteHex = normalizeQuoteHex(quote);
      if (quoteHex === null) {
        return refusingVerifier(quote, "quote is neither hex nor base64", options.implementation ?? "unavailable");
      }

      const resolved = resolveDcapVerifierBinary(options.binaryPath, { searchPath: options.searchPath });
      if (!resolved.path) {
        return refusingVerifier(quoteHex, resolved.reason ?? "no DCAP engine available", options.implementation ?? "unavailable");
      }
      if (options.expectedBinarySha256) {
        const digest = fileSha256(resolved.path);
        const expected = options.expectedBinarySha256.trim().toLowerCase();
        if (digest === null || digest !== expected) {
          return refusingVerifier(
            quoteHex,
            "the resolved engine's SHA-256 does not match expectedBinarySha256",
            options.implementation ?? `subprocess:${resolved.path}`
          );
        }
      }

      let collateral = options.collateral;
      if (!collateral) {
        if (options.fetchCollateral === false) {
          return refusingVerifier(quoteHex, "no collateral supplied and fetching is disabled", options.implementation ?? `subprocess:${resolved.path}`);
        }
        try {
          collateral = (await cache.get(quoteHex, context.nowMs ?? Date.now())).collateral;
        } catch (error) {
          return refusingVerifier(
            quoteHex,
            error instanceof Error ? `collateral unavailable: ${error.message}` : "collateral unavailable",
            options.implementation ?? `subprocess:${resolved.path}`
          );
        }
      }

      const nowMs = context.nowMs ?? Date.now();
      const request = buildDcapEngineRequest(
        quoteHex,
        collateral,
        Math.floor(nowMs / 1000),
        context.acceptedTcbStatuses
      );
      const verdict = await runDcapEngine(resolved.path, request, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

      // The engine read the same bytes we did. If it reports a different TD, one
      // of us is not looking at the quote about to be trusted.
      const disagreement = verdict.verified ? engineReportDisagreement(quoteHex, verdict.report) : null;
      const implementation = options.implementation ?? verdict.engine;
      if (disagreement) {
        return refusingVerifier(quoteHex, disagreement, implementation);
      }
      return preparedDcapVerifier(quoteHex, verdict, implementation);
    }
  };
}

/** A verifier bound to one quote, replaying an engine verdict for exactly it. */
export function preparedDcapVerifier(
  quoteHex: string,
  verdict: DcapEngineVerdictV1,
  implementation: string
): TdxChainVerifier {
  const expected = quoteHex.toLowerCase();
  return {
    implementation,
    verifyChain(rawQuote: string) {
      // Compare on BYTES, not spelling: evidence may arrive base64 where the
      // engine was prepared from hex, and a spelling mismatch must not read as a
      // substituted quote.
      const offered = normalizeQuoteHex(rawQuote);
      if (offered === null || offered !== expected) {
        return { verified: false, detail: "this verifier was prepared for a different quote" };
      }
      return {
        verified: verdict.verified === true,
        ...(verdict.tcbStatus ? { tcbStatus: verdict.tcbStatus } : {}),
        detail: verdict.verified
          ? `engine=${implementation} qe=${verdict.qeTcbStatus ?? "?"} platform=${verdict.platformTcbStatus ?? "?"}`
          : verdict.error ?? "engine refused the quote"
      };
    }
  };
}

/** A verifier that refuses everything, carrying the reason for the audit trail. */
function refusingVerifier(quoteHex: string, reason: string, implementation: string): TdxChainVerifier {
  return preparedDcapVerifier(
    quoteHex,
    {
      verified: false,
      tcbStatus: null,
      qeTcbStatus: null,
      platformTcbStatus: null,
      advisoryIds: [],
      report: null,
      error: reason,
      engine: implementation
    },
    implementation
  );
}

/** True when `path` looks like an absolute filesystem path (for CLI diagnostics). */
export function isAbsolutePath(path: string): boolean {
  return isAbsolute(path);
}
