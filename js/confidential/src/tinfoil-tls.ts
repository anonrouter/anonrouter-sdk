// Independently observe the TLS key a Tinfoil enclave actually serves.
//
// WHY THIS FILE EXISTS. Tinfoil's verification document reports the enclave's
// TLS public-key fingerprint twice: once as `enclaveMeasurement.
// tlsPublicKeyFingerprint` and once as `tlsPublicKey`. Both are copies of one
// field of one AMD SEV-SNP report, so a verifier that compares them to each
// other has checked nothing: the comparison passes for every document, including
// a wholly fabricated one. Binding the attested key to anything real means
// opening a connection to the enclave and reading the key off the wire.
//
// WHAT IT DOES. One content-free HEAD request over a PRIVATE HTTPS agent. The
// socket is usable only after ordinary PKI and hostname validation succeeds AND
// the peer certificate's SPKI SHA-256 equals the attested fingerprint exactly.
// The private agent is load-bearing rather than tidy: a shared agent could hand
// back a socket opened by some unrelated unpinned request, which would never
// have run this callback. No credential, no body, no prompt, no account
// identity is sent, and the response body is discarded unread.
//
// NODE ONLY, AND FAIL-CLOSED. Every Node builtin below is reached through a
// non-literal dynamic specifier, so `@anonrouter/confidential` still imports
// cleanly in a browser and this module is never statically resolved there. A
// browser cannot inspect a peer certificate at all, so there is no degraded
// mode: `observeTinfoilTlsSpki()` throws `TinfoilTlsUnavailableError` and the
// caller turns that into a failed verdict. It never returns an unpinned result.

/** The peer's key is not the key the verified AMD report attested, or the peer
 *  failed ordinary certificate/hostname validation. */
export class TinfoilTlsPinError extends Error {
  constructor(detail = "peer SPKI does not match the attested key") {
    super(`Tinfoil TLS pinning failed: ${detail}`);
    this.name = "TinfoilTlsPinError";
  }
}

/** This runtime cannot observe a peer certificate (a browser, or a bundle with
 *  Node's TLS stack shimmed out). */
export class TinfoilTlsUnavailableError extends Error {
  constructor() {
    super("Tinfoil TLS pinning requires Node.js: this runtime cannot observe a peer certificate");
    this.name = "TinfoilTlsUnavailableError";
  }
}

export interface TinfoilTlsProbeOptions {
  /** HTTPS origin of the enclave, e.g. `https://inference.tinfoil.sh`. */
  origin: string;
  /** SHA-256 of the SPKI the verified AMD report attested (64 hex chars). */
  expectedTlsSpki: string;
  /** Handshake + response deadline. */
  timeoutMs?: number;
  /** Trust ONLY this PEM instead of the system store. Exists so the negative
   *  tests can drive a real local TLS server; production passes nothing and gets
   *  ordinary public PKI validation. */
  ca?: string;
}

interface NodeTlsStack {
  request: (options: Record<string, unknown>, onResponse: (response: NodeResponse) => void) => NodeRequest;
  Agent: new (options: Record<string, unknown>) => unknown;
  checkServerIdentity: (host: string, cert: NodePeerCertificate) => Error | undefined;
  createHash: (algorithm: string) => { update(data: Uint8Array): { digest(encoding: string): string } };
  X509Certificate: new (raw: Uint8Array) => { publicKey: { export(options: { type: string; format: string }): Uint8Array } };
}

interface NodePeerCertificate {
  raw?: Uint8Array;
}

interface NodeRequest {
  on(event: string, listener: (arg?: unknown) => void): unknown;
  once(event: string, listener: (arg?: unknown) => void): unknown;
  setTimeout(ms: number, listener: () => void): unknown;
  destroy(error?: Error): unknown;
  end(): unknown;
}

interface NodeResponse {
  statusCode?: number;
  resume(): unknown;
  on(event: string, listener: (arg?: unknown) => void): unknown;
}

const DEFAULT_TIMEOUT_MS = 20_000;

/** Load Node's TLS stack through non-literal specifiers so a browser build never
 *  has to resolve it. Returns null off Node. */
async function loadNodeTlsStack(): Promise<NodeTlsStack | null> {
  const httpsSpecifier = "node:https";
  const tlsSpecifier = "node:tls";
  const cryptoSpecifier = "node:crypto";
  try {
    const [https, tls, crypto] = await Promise.all([
      import(httpsSpecifier) as Promise<Record<string, unknown>>,
      import(tlsSpecifier) as Promise<Record<string, unknown>>,
      import(cryptoSpecifier) as Promise<Record<string, unknown>>
    ]);
    const stack = {
      request: https.request,
      Agent: https.Agent,
      checkServerIdentity: tls.checkServerIdentity,
      createHash: crypto.createHash,
      X509Certificate: crypto.X509Certificate
    };
    const complete = Object.values(stack).every((value) => typeof value === "function");
    return complete ? (stack as unknown as NodeTlsStack) : null;
  } catch {
    return null;
  }
}

/**
 * Open one pinned, content-free connection to `origin` and return the peer SPKI
 * SHA-256 actually observed on it.
 *
 * Resolves ONLY when ordinary PKI/hostname validation passed and the observed
 * SPKI equals `expectedTlsSpki`. Rejects with `TinfoilTlsPinError` on a
 * mismatch or a certificate failure, and with `TinfoilTlsUnavailableError` off
 * Node. There is no unpinned fallback: a caller cannot reach a result here
 * without the pin having held.
 */
export async function observeTinfoilTlsSpki(options: TinfoilTlsProbeOptions): Promise<string> {
  const target = new URL(options.origin);
  if (target.protocol !== "https:") {
    throw new TinfoilTlsPinError(`refused non-HTTPS origin ${target.origin}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(options.expectedTlsSpki)) {
    throw new TinfoilTlsPinError("attested key is not a SHA-256 SPKI fingerprint");
  }
  const stack = await loadNodeTlsStack();
  if (!stack) throw new TinfoilTlsUnavailableError();

  const expected = options.expectedTlsSpki.toLowerCase();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  // A private agent, used for this one request and then destroyed. Never a
  // shared pool: a reused socket would skip checkServerIdentity entirely.
  const agent = new stack.Agent({
    keepAlive: false,
    maxSockets: 1,
    ...(options.ca ? { ca: options.ca } : {})
  });
  let observed: string | null = null;

  try {
    const status = await new Promise<number>((resolve, reject) => {
      const request = stack.request({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port ? Number(target.port) : 443,
        path: "/",
        // HEAD, no headers, no body. The handshake is the entire point of the
        // request; the response is only proof that it completed.
        method: "HEAD",
        agent,
        checkServerIdentity: (host: string, cert: NodePeerCertificate) => {
          const standardError = stack.checkServerIdentity(host, cert);
          if (standardError) return standardError;
          if (!cert.raw) return new TinfoilTlsPinError("peer presented no certificate to pin");
          const actual = stack.createHash("sha256")
            .update(new stack.X509Certificate(cert.raw).publicKey.export({ type: "spki", format: "der" }))
            .digest("hex");
          if (actual !== expected) return new TinfoilTlsPinError();
          observed = actual;
          return undefined;
        }
      }, (response) => {
        response.resume();
        resolve(response.statusCode ?? 0);
      });
      request.setTimeout(timeoutMs, () => request.destroy(new Error("Tinfoil TLS observation timed out")));
      request.once("error", (error?: unknown) => reject(error instanceof Error ? error : new TinfoilTlsPinError()));
      request.end();
    });
    // Belt and braces. A response that arrived without the callback having run
    // would mean the socket was not the one we validated, so refuse it rather
    // than reporting an observation nobody made.
    if (observed === null) {
      throw new TinfoilTlsPinError(`connection completed (HTTP ${status}) without a pinned certificate observation`);
    }
    return observed;
  } finally {
    (agent as { destroy?: () => void }).destroy?.();
  }
}
