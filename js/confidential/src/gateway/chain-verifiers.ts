// Generic DCAP chain-verifier adapters, for an engine you wrote yourself. NODE ONLY.
//
// FOR THE OFFICIAL PATH, USE `@anonrouter/confidential/dcap` INSTEAD.
// `createAnonRouterDcapVerifier()` there speaks the exact wire contract of
// AnonRouter's reviewed offline engine, acquires the Intel-signed collateral that
// engine requires, and cross-checks the engine's report against the quote. This
// module deliberately does NOT: it speaks a minimal contract of its own, so an
// operator who already has some verification service or wrapper script can plug
// it in without writing an adapter.
//
//   createSubprocessChainVerifier  spawn an executable you control. It receives
//                                  the raw quote hex on stdin and must print
//                                  `{"verified":bool,"tcbStatus":"..."}`. This is
//                                  NOT the AnonRouter engine's contract, which
//                                  takes a JSON request including collateral;
//                                  point this at your own wrapper, not at
//                                  `anonrouter-dcap-verifier` directly.
//
//   createRemoteChainVerifier      POST `{quote}` to a Quote Verification Service.
//                                  Convenient, and a REAL trust transfer: you are
//                                  now trusting that service's answer about
//                                  whether the hardware is genuine. Never point it
//                                  at a service run by the party you are verifying,
//                                  which the SDK cannot detect for you.
//
// FAIL CLOSED, ALWAYS. Every failure mode here means "not verified": a missing
// binary, a timeout, a crash, a non-zero exit, output that is not JSON, output
// that is too large, a malformed verdict, an unreachable service, an HTTP error.
// There is no path where an error becomes a pass, and none of these ever throw
// into the verifier: they return `{ verified: false }` so the required
// `quote_signature_chain` check fails loudly instead of vanishing.
//
// Import from "@anonrouter/confidential/chain-verifiers". Importing this module
// in a browser build will fail to resolve node:child_process, by design.

import { execFile } from "node:child_process";
import type { TdxChainVerifier } from "./verify.js";

/** A verdict is small; anything larger means something is wrong. */
const MAX_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * The JSON an engine wired through THIS module must print on stdout.
 *
 * Note the spelling: `tcbStatus`, camelCase. AnonRouter's own reviewed engine
 * emits `tcb_status` and reads a JSON request rather than a bare quote, so it is
 * not compatible with this adapter. Use `@anonrouter/confidential/dcap` for that
 * engine; this shape is for a wrapper you control.
 */
export interface DcapEngineVerdict {
  verified: boolean;
  tcbStatus?: string | null;
  qeTcbStatus?: string | null;
  platformTcbStatus?: string | null;
  advisoryIds?: string[];
  /** Content-free reason, present when `verified` is false. */
  error?: string | null;
}

export interface SubprocessChainVerifierOptions {
  /**
   * Path to the executable. REQUIRED and never inferred: silently verifying with
   * an engine the caller did not name is exactly the substitution this component
   * exists to prevent.
   */
  binaryPath: string;
  /** Extra arguments before the quote. The quote is passed on stdin, not argv. */
  args?: string[];
  /** Hard deadline. Real verification is milliseconds; this bounds pathology. */
  timeoutMs?: number;
  /** Label carried into the verdict for the audit trail. */
  implementation?: string;
}

/** Parse an engine's stdout into a verdict, or null if it is unusable. */
function parseEngineVerdict(stdout: string): DcapEngineVerdict | null {
  if (stdout.length === 0 || stdout.length > MAX_OUTPUT_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;
  // `verified` must be a real boolean. A truthy string or a missing field is a
  // malformed verdict, and coercing it would invent a pass out of noise.
  if (typeof record.verified !== "boolean") return null;
  const status = record.tcbStatus;
  return {
    verified: record.verified,
    tcbStatus: typeof status === "string" ? status : null,
    error: typeof record.error === "string" ? record.error : null
  };
}

/**
 * Verify quotes by spawning a DCAP engine.
 *
 * The returned verifier is SYNCHRONOUS because `verifyGatewayAttestation` is
 * pure and synchronous, so the quote must be verified before you call it: use
 * `prepare()` to run the engine, then pass the verifier in. `verifyChain` then
 * only replays the prepared verdict, and refuses any quote it was not prepared
 * for, so a second quote can never inherit the first one's pass.
 */
export function createSubprocessChainVerifier(options: SubprocessChainVerifierOptions): {
  prepare(quote: string): Promise<TdxChainVerifier>;
} {
  const implementation = options.implementation ?? `subprocess:${options.binaryPath}`;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  async function runEngine(quote: string): Promise<DcapEngineVerdict> {
    if (typeof quote !== "string" || !/^[0-9a-fA-F]+$/.test(quote) || quote.length % 2 !== 0) {
      return { verified: false, tcbStatus: null, error: "quote is not even-length hex" };
    }
    return new Promise((resolve) => {
      let settled = false;
      const done = (verdict: DcapEngineVerdict) => {
        if (!settled) {
          settled = true;
          resolve(verdict);
        }
      };
      let child;
      try {
        child = execFile(
          options.binaryPath,
          options.args ?? [],
          { timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES, encoding: "utf8" },
          (error, stdout) => {
            if (error) {
              // Missing binary, non-zero exit, timeout, oversized output: all refusals.
              done({ verified: false, tcbStatus: null, error: `engine failed: ${error.code ?? "error"}` });
              return;
            }
            const verdict = parseEngineVerdict(String(stdout).trim());
            done(verdict ?? { verified: false, tcbStatus: null, error: "engine produced no usable verdict" });
          }
        );
      } catch (error) {
        done({ verified: false, tcbStatus: null, error: "engine could not be spawned" });
        return;
      }
      // The quote goes on stdin, never argv: a multi-kilobyte hex blob in a
      // command line is a process-listing leak and an ARG_MAX hazard.
      try {
        child.stdin?.end(quote);
      } catch {
        done({ verified: false, tcbStatus: null, error: "engine stdin could not be written" });
      }
      child.on("error", () => done({ verified: false, tcbStatus: null, error: "engine could not be spawned" }));
    });
  }

  return {
    async prepare(quote: string): Promise<TdxChainVerifier> {
      const verdict = await runEngine(quote);
      return preparedChainVerifier(quote, verdict, implementation);
    }
  };
}

export interface RemoteChainVerifierOptions {
  /**
   * The verification service endpoint. It receives `{ quote }` as JSON and must
   * answer with a DcapEngineVerdict.
   *
   * TRUST NOTE: this moves the "is this real silicon" decision to that service.
   * Pointing it at anything operated by the party you are verifying makes the
   * whole check circular, and the SDK cannot detect that for you.
   */
  url: string;
  fetch?: (input: string, init?: RequestInit) => Promise<Response>;
  timeoutMs?: number;
  headers?: Record<string, string>;
  implementation?: string;
}

/** Verify quotes by asking a remote Quote Verification Service. */
export function createRemoteChainVerifier(options: RemoteChainVerifierOptions): {
  prepare(quote: string): Promise<TdxChainVerifier>;
} {
  const implementation = options.implementation ?? `remote:${options.url}`;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetch ?? (globalThis.fetch.bind(globalThis) as RemoteChainVerifierOptions["fetch"])!;

  return {
    async prepare(quote: string): Promise<TdxChainVerifier> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let verdict: DcapEngineVerdict;
      try {
        const response = await fetchImpl(options.url, {
          method: "POST",
          cache: "no-store",
          headers: { "content-type": "application/json", ...(options.headers ?? {}) },
          body: JSON.stringify({ quote }),
          signal: controller.signal
        });
        if (!response.ok) {
          verdict = { verified: false, tcbStatus: null, error: `verification service returned ${response.status}` };
        } else {
          const parsed = parseEngineVerdict(JSON.stringify(await response.json()));
          verdict = parsed ?? { verified: false, tcbStatus: null, error: "verification service returned no usable verdict" };
        }
      } catch {
        verdict = { verified: false, tcbStatus: null, error: "verification service was unreachable" };
      } finally {
        clearTimeout(timer);
      }
      return preparedChainVerifier(quote, verdict, implementation);
    }
  };
}

/**
 * Wrap a verdict as a `TdxChainVerifier` bound to the exact quote it describes.
 *
 * The quote check is the load-bearing part. Without it, a verifier prepared for
 * quote A would happily report "verified" for quote B, which is the substitution
 * the whole port exists to prevent.
 */
export function preparedChainVerifier(
  quote: string,
  verdict: DcapEngineVerdict,
  implementation: string
): TdxChainVerifier {
  const expected = quote.toLowerCase();
  return {
    implementation,
    verifyChain(rawQuote: string) {
      if (typeof rawQuote !== "string" || rawQuote.toLowerCase() !== expected) {
        return { verified: false, detail: "this verifier was prepared for a different quote" };
      }
      return {
        verified: verdict.verified === true,
        ...(verdict.tcbStatus ? { tcbStatus: verdict.tcbStatus } : {}),
        ...(verdict.verified ? {} : { detail: verdict.error ?? "engine refused the quote" })
      };
    }
  };
}
