// Opt-in Node operation: one normally validated TLS socket ever.
// SDK defaults remain unchanged. The built-in verifier establishes
// trust from nonce-bound evidence and THIS socket's observed SPKI.
import { Agent, request, type RequestOptions } from "node:https";
import type { ClientRequest } from "node:http";
import { connect, checkServerIdentity, type ConnectionOptions, type TLSSocket } from "node:tls";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import type { Duplex } from "node:stream";
import { isIP } from "node:net";
import dns from "node:dns";
import { assertGatewayPolicySecurityFloor } from "./authority.js";
import type { GatewayMeasurementPolicy } from "./policy.js";
import { verifyGatewayAttestation, type TdxChainVerifier, type TdxChainVerifierFactory,
  type GatewayAttestationEvidence, type GatewayVerificationResult } from "./verify.js";

export class RetainedGatewayError extends Error {
  constructor(readonly code: "configuration" | "tls_certificate" | "untrusted" | "connection_lost" | "cancelled" | "expired" | "timeout" | "transport" | "redirect" | "busy",
    readonly dispatchPhase: "before_http" | "may_have_dispatched" = "before_http") {
    super(`Retained gateway operation refused (${code}).`);
    this.name = "RetainedGatewayError";
  }
  /**
   * The content-free verdict, when evidence was fetched on the retained socket
   * and verified but not accepted. Diagnostic only: it never authorizes
   * anything, and the socket is already closed.
   */
  verdict?: GatewayVerificationResult;
}
// Ownership, not a public code/dispatchPhase, grants one fresh preparation.
// Only this module's initial socket failure path can mint these capabilities.
const initialConnectionRefusals = new WeakMap<RetainedGatewayError, State>();
export function consumeInitialConnectionRefusal(error: unknown): boolean {
  if (!(error instanceof RetainedGatewayError)) return false;
  const owner = initialConnectionRefusals.get(error);
  if (!owner?.closedJoined || owner.handshakeComplete || owner.httpWritten) return false;
  initialConnectionRefusals.delete(error);
  return true;
}
export interface RetainedGatewayOptions {
  origin: string;
  policy: GatewayMeasurementPolicy;
  chainVerifier: TdxChainVerifier | TdxChainVerifierFactory;
  approvalExpiresAtMs?: number;
  signal?: AbortSignal;
  /** Candidate cap, measured from before the initial handshake, NOT an
   * operationally accepted serving grace. Caller can only tighten 180 seconds. */
  preDispatchBudgetMs?: number;
  /** Private orchestration deadline. Can only shorten the primitive's cap. */
  preparationDeadlineMs?: number;
  requestTimeoutMs?: number;
  ca?: string;
  /** Explicit acknowledgement for a platform kind this SDK release has not
   * qualified (see GATEWAY_PLATFORM_QUALIFIED). It relaxes nothing else. */
  unqualifiedPlatformPilot?: boolean;
  /** Only policy/approval metadata may change. The quote and socket never do. */
  refreshPolicy?: (signal: AbortSignal) => Promise<{ policy: GatewayMeasurementPolicy; approvalExpiresAtMs?: number }>;
}
export interface RetainedGatewayOperation {
  readonly identity: Readonly<{ origin: string; nonce: string; tlsSpkiSha256: string; appId: string; instanceId: string; composeHash: string; expiresAtMs: number }>;
  readonly verdict: GatewayVerificationResult;
  readonly rawEvidence: GatewayAttestationEvidence;
  assertDispatchAllowed(): void;
  fetch(url: string, init?: RequestInit): Promise<Response>;
  close(): void;
}
interface State {
  socket?: TLSSocket; observedPin?: string; opened: boolean; authorized: boolean;
  closed: boolean; lost: boolean; busy: boolean; refusal?: RetainedGatewayError; guard(): void;
  handshakeComplete?: boolean; httpWritten?: boolean;
  closedJoined?: boolean;
}
const fail = (code: RetainedGatewayError["code"], phase: RetainedGatewayError["dispatchPhase"] = "before_http") => new RetainedGatewayError(code, phase);
const optionKeys = new Set(["origin", "policy", "chainVerifier", "approvalExpiresAtMs", "signal", "preDispatchBudgetMs", "preparationDeadlineMs", "requestTimeoutMs", "ca", "refreshPolicy", "unqualifiedPlatformPilot"]);
const initKeys = new Set(["method", "headers", "body", "signal", "credentials", "cache", "redirect"]);
function exact(value: object, keys: Set<string>) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).some(key => typeof key !== "string" || !keys.has(key))) throw fail("configuration");
}
function limit(value: number | undefined, fallback: number, max: number) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > max) throw fail("configuration");
  return result;
}
function snapshotPolicy(value: GatewayMeasurementPolicy): GatewayMeasurementPolicy {
  const policy = structuredClone(value);
  assertGatewayPolicySecurityFloor(policy);
  if (!Number.isSafeInteger(policy.maxEvidenceAgeMs) || policy.maxEvidenceAgeMs <= 0) throw fail("configuration");
  return policy;
}
function deepFreeze<T>(value: T): T {
  const pending: unknown[] = [value]; const seen = new WeakSet<object>();
  while (pending.length) {
    const item = pending.pop();
    if (!item || typeof item !== "object" || seen.has(item)) continue;
    seen.add(item); pending.push(...Object.values(item)); Object.freeze(item);
  }
  return value;
}
class SoleSocketAgent extends Agent {
  private socketJoined: Promise<void> = Promise.resolve();
  private readonly lookupJoins: Promise<void>[] = [];
  private readonly requestJoins: Promise<void>[] = [];
  trackRequest(req: ClientRequest): void {
    this.requestJoins.push(new Promise(resolve => req.once("close", resolve)));
  }
  async joinClosed(): Promise<void> {
    await Promise.all([this.socketJoined, ...this.lookupJoins, ...this.requestJoins]);
  }
  constructor(private readonly state: State, private readonly hostname: string, private readonly caPem?: string) {
    super({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1, maxCachedSessions: 0 });
  }
  override createConnection(options: ConnectionOptions, callback?: (error: Error | null, socket: Duplex) => void): TLSSocket | undefined {
    if (!callback) throw fail("configuration");
    // A pool is NEVER allowed to replace the attested connection. Even after
    // remote close, no second DNS lookup, TCP connection or TLS handshake occurs.
    if (this.state.opened || this.state.closed || this.state.lost) {
      callback(fail("connection_lost"), this.state.socket!); return undefined;
    }
    try { this.state.guard(); }
    catch (error) {
      callback(error instanceof RetainedGatewayError ? error : fail("transport"), this.state.socket!);
      return undefined;
    }
    this.state.opened = true;
    const tlsOptions: ConnectionOptions & { autoSelectFamily: boolean } = { ...options,
      ca: this.caPem, rejectUnauthorized: true, session: undefined, autoSelectFamily: false,
      servername: isIP(this.hostname) ? undefined : this.hostname,
      checkServerIdentity: (_host, certificate) => checkServerIdentity(this.hostname, certificate),
      lookup: (hostname, lookupOptions, callback) => {
        let joined!: () => void;
        this.lookupJoins.push(new Promise<void>(resolve => { joined = resolve; }));
        try {
          dns.lookup(hostname, lookupOptions, (error, address, family) => {
            try { callback(error, address, family); } finally { joined(); }
          });
        } catch (error) { joined(); throw error; }
      } };
    const socket = connect(tlsOptions);
    this.state.socket = socket;
    this.socketJoined = new Promise(resolve => socket.once("close", resolve));
    let settled = false;
    const finish = (error?: Error, initialRetry = false) => {
      if (settled) return; settled = true; clearTimeout(timer);
      if (initialRetry && error instanceof RetainedGatewayError && !this.state.handshakeComplete && !this.state.httpWritten) initialConnectionRefusals.set(error, this.state);
      if (error) { this.state.lost = true; socket.destroy(); }
      callback(error ?? null, socket);
    };
    const timer = setTimeout(() => finish(fail("timeout"), true), 10_000); timer.unref();
    socket.once("error", error => finish(fail("tls_certificate"), (error as NodeJS.ErrnoException).code === "ECONNRESET"));
    socket.once("close", () => { this.state.lost = true; finish(fail("connection_lost")); });
    socket.once("secureConnect", () => {
      this.state.handshakeComplete = true;
      try {
        const certificate = socket.getPeerCertificate();
        if (!socket.authorized || !certificate.raw || checkServerIdentity(this.hostname, certificate)) throw fail("tls_certificate");
        this.state.observedPin = createHash("sha256").update(new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" })).digest("hex");
        this.state.guard();
        finish();
      } catch (error) { finish(error instanceof RetainedGatewayError ? error : fail("tls_certificate")); }
    });
    return undefined;
  }
  override reuseSocket(socket: Duplex, req: ClientRequest): void {
    // Called synchronously before Node's request receives the idle socket. This
    // guard also covers the reuse path, where no TLS callback executes again.
    try {
      if (socket !== this.state.socket || !this.state.authorized) throw fail("connection_lost");
      this.state.guard();
    } catch (error) {
      // Agent may invoke its hooks outside the exchange's Promise executor.
      // Deliver refusal through ClientRequest, without an uncaught throw or
      // allowing core's subsequent socket assignment to flush queued HTTP.
      this.state.refusal = error instanceof RetainedGatewayError ? error : fail("transport");
      req.destroy(this.state.refusal);
      socket.destroy(); this.state.lost = true;
      return;
    }
    super.reuseSocket(socket, req);
  }
  override destroy(): void {
    // Includes the provisional handshake, before Agent owns it.
    this.state.socket?.destroy(); super.destroy();
  }
}

export async function openRetainedGatewayOperation(options: RetainedGatewayOptions): Promise<RetainedGatewayOperation> {
  exact(options, optionKeys);
  if (typeof options.origin !== "string" || !options.chainVerifier
      || (options.ca !== undefined && (typeof options.ca !== "string" || !options.ca.trim()))
      || (options.refreshPolicy !== undefined && typeof options.refreshPolicy !== "function")
      || (options.unqualifiedPlatformPilot !== undefined && typeof options.unqualifiedPlatformPilot !== "boolean")
      || (options.preparationDeadlineMs !== undefined && !Number.isFinite(options.preparationDeadlineMs))
      || (options.approvalExpiresAtMs !== undefined && (!Number.isSafeInteger(options.approvalExpiresAtMs) || options.approvalExpiresAtMs <= 0))) throw fail("configuration");
  let origin: URL;
  try { origin = new URL(options.origin); } catch { throw fail("configuration"); }
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== "/") throw fail("configuration");
  let policy = snapshotPolicy(options.policy);
  const nonce = randomBytes(32).toString("hex");
  const signal = options.signal;
  const preDispatchBudget = limit(options.preDispatchBudgetMs, 180_000, 180_000);
  const requestTimeout = limit(options.requestTimeoutMs, 900_000, 900_000);
  const started = performance.now();
  const preparationDeadline = Math.min(started + preDispatchBudget, options.preparationDeadlineMs ?? Infinity);
  let evidenceExpiry = Infinity;
  let approvalExpiry = options.approvalExpiresAtMs ?? Infinity;
  let activeCancel: ((error: RetainedGatewayError) => void) | undefined;
  let paidAttempted = false;
  const state: State = { opened: false, authorized: false, closed: false, lost: false, busy: false,
    guard() {
      if (state.closed || signal?.aborted) throw fail("cancelled");
      if (state.refusal) throw state.refusal;
      if (state.lost || state.socket?.destroyed || state.socket?.writableEnded) throw fail("connection_lost");
      if (performance.now() >= preparationDeadline || Date.now() >= Math.min(evidenceExpiry, approvalExpiry)) throw fail("expired");
    } };
  const hostname = origin.hostname.replace(/^\[|\]$/g, "");
  const agent = new SoleSocketAgent(state, hostname, options.ca);
  const close = () => {
    if (state.closed) return; state.closed = true;
    activeCancel?.(fail("cancelled", "may_have_dispatched"));
    agent.destroy(); signal?.removeEventListener("abort", abortOperation);
  };
  const abortOperation = () => close();
  signal?.addEventListener("abort", abortOperation, { once: true });

  async function boundedPreparation<T>(run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    state.guard();
    const remaining = preparationDeadline - performance.now();
    const timeoutSignal = AbortSignal.timeout(Math.max(1, Math.floor(Math.min(10_000, remaining))));
    const prepareSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    return await new Promise<T>((resolve, reject) => {
      let settled = false;
      const complete = (value?: T, error?: RetainedGatewayError) => {
        if (settled) return; settled = true;
        prepareSignal.removeEventListener("abort", abort);
        if (error) reject(error); else resolve(value!);
      };
      const abort = () => complete(undefined, fail(signal?.aborted ? "cancelled" : "timeout"));
      prepareSignal.addEventListener("abort", abort, { once: true });
      Promise.resolve().then(() => run(prepareSignal)).then(value => complete(value), () => complete(undefined, fail("untrusted")));
      if (prepareSignal.aborted) abort();
    });
  }

  async function exchange(input: string, init: RequestInit = {}, challenge = false): Promise<Response> {
    exact(init, initKeys); state.guard();
    if (state.busy) throw fail("busy");
    if (!challenge && !state.authorized) throw fail("untrusted");
    let target: URL;
    try { target = new URL(input); } catch { throw fail("configuration"); }
    if (target.origin !== origin.origin || target.username || target.password || target.hash
        || (!challenge && target.pathname === "/v1/gateway/attestation")) throw fail("configuration");
    if ((init.credentials !== undefined && init.credentials !== "omit") || (init.redirect !== undefined && init.redirect !== "error")) throw fail("configuration");
    const method = (init.method ?? "GET").toUpperCase();
    if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)) throw fail("configuration");
    const contentPaths = new Set(["/v1/chat/completions", "/v1/e2ee/chat/completions", "/v1/images/generations", "/v1/audio/speech", "/v1/embeddings"]);
    const paid = !challenge && contentPaths.has(target.pathname);
    if (!challenge && !(target.pathname === "/v1/tee/attestation" || paid)) throw fail("configuration");
    if (paid && (method !== "POST" || paidAttempted)) throw fail("configuration");
    if (!challenge && !paid && !["GET", "POST"].includes(method)) throw fail("configuration");
    const headers = new Headers(init.headers);
    headers.forEach((_value, name) => { if (["host", "connection", "content-length", "transfer-encoding", "upgrade", "trailer", "expect", "authorization", "cookie"].includes(name) || name.startsWith("proxy-")) throw fail("configuration"); });
    if (headers.has("accept-encoding") && headers.get("accept-encoding") !== "identity") throw fail("configuration");
    headers.set("accept-encoding", "identity");
    let body: string | Uint8Array | undefined;
    if (init.body != null) {
      if (typeof init.body === "string") body = init.body;
      else if (init.body instanceof Uint8Array) body = Uint8Array.from(init.body);
      else if (init.body instanceof ArrayBuffer) body = new Uint8Array(init.body.slice(0));
      else throw fail("configuration");
    }
    if (["GET", "HEAD"].includes(method) && body !== undefined) throw fail("configuration");
    const requestSignal = signal && init.signal ? AbortSignal.any([signal, init.signal]) : signal ?? init.signal;
    if (requestSignal?.aborted) throw fail("cancelled");
    const requestHeaders: Record<string, string> = {}; headers.forEach((value, name) => { requestHeaders[name] = value; });
    if (paid) paidAttempted = true;
    state.busy = true;
    return await new Promise<Response>((resolve, reject) => {
      let done = false; let req: ClientRequest | undefined; let wireDispatched = false;
      const finish = () => { if (done) return; done = true; clearTimeout(timer); requestSignal?.removeEventListener("abort", abort); activeCancel = undefined; state.busy = false; };
      const terminate = (error: RetainedGatewayError) => { if (done) return; req?.destroy(error); reject(error); finish(); state.lost = true; agent.destroy(); };
      const abort = () => terminate(fail("cancelled", wireDispatched ? "may_have_dispatched" : "before_http"));
      activeCancel = terminate;
      const timeout = !paid ? Math.min(30_000, preparationDeadline - performance.now()) : requestTimeout;
      const timer = setTimeout(() => terminate(fail("timeout", wireDispatched ? "may_have_dispatched" : "before_http")), Math.max(1, timeout)); timer.unref();
      try {
        req = request({ protocol: "https:", hostname, port: origin.port || 443,
          path: target.pathname + target.search, method, headers: requestHeaders, agent } satisfies RequestOptions, response => {
          if ((response.statusCode ?? 0) >= 300 && (response.statusCode ?? 0) < 400 || response.headers["content-encoding"] && response.headers["content-encoding"] !== "identity") {
            response.destroy(); terminate(fail("redirect", "may_have_dispatched")); return;
          }
          if (response.headers.connection?.toLowerCase().split(/\s*,\s*/).includes("close")) {
            if (!paid) {
              response.destroy(); terminate(fail("connection_lost", "may_have_dispatched")); return;
            }
            // Drain can close the connection AFTER the final paid response.
            // Keep consuming that admitted response; forbid any future use.
            state.lost = true;
          }
          const responseHeaders = new Headers();
          for (let index = 0; index < response.rawHeaders.length; index += 2) responseHeaders.append(response.rawHeaders[index]!, response.rawHeaders[index + 1]!);
          const bodyless = method === "HEAD" || [204, 205, 304].includes(response.statusCode ?? 0);
          if (bodyless) {
            response.once("end", finish); response.resume();
            try { resolve(new Response(null, { status: response.statusCode!, headers: responseHeaders })); }
            catch { terminate(fail("transport", "may_have_dispatched")); }
            return;
          }
          const iterator = response[Symbol.asyncIterator]();
          const stream = new ReadableStream<Uint8Array>({
            async pull(controller) {
              try {
                const next = await iterator.next();
                if (next.done) { finish(); controller.close(); }
                else controller.enqueue(new Uint8Array(next.value));
              } catch (error) { finish(); state.lost = true; agent.destroy(); controller.error(error instanceof RetainedGatewayError ? error : fail("transport", "may_have_dispatched")); }
            },
            async cancel() { terminate(fail("cancelled", "may_have_dispatched")); await iterator.return?.(); }
          });
          try { resolve(new Response(stream, { status: response.statusCode!, headers: responseHeaders })); }
          catch { terminate(fail("transport", "may_have_dispatched")); }
        });
        agent.trackRequest(req);
        req.once("socket", socket => {
          try {
            if (socket !== state.socket) throw fail("connection_lost");
            // Also covers core's asynchronous queued/free-socket handoff,
            // which need not invoke Agent.reuseSocket at all.
            state.guard();
            if (requestSignal?.aborted) throw fail("cancelled");
            wireDispatched = true;
            state.httpWritten = true;
          } catch (error) { terminate(error instanceof RetainedGatewayError ? error : fail("transport")); }
        });
        req.once("error", error => terminate(state.refusal ?? (error instanceof RetainedGatewayError ? error : fail("transport", wireDispatched ? "may_have_dispatched" : "before_http"))));
        requestSignal?.addEventListener("abort", abort, { once: true });
        state.guard(); if (requestSignal?.aborted) return abort();
        req.end(body);
      } catch (error) { terminate(error instanceof RetainedGatewayError ? error : fail("transport")); }
    });
  }
  try {
    state.guard();
    const response = await exchange(`${origin.origin}/v1/gateway/attestation?nonce=${nonce}`, { method: "GET", credentials: "omit", headers: { accept: "application/json" } }, true);
    if (!response.ok || !response.body) throw fail("untrusted");
    // Bound the untrusted challenge envelope before parsing/verifying it.
    const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
    while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 2_097_152) { await reader.cancel(); throw fail("untrusted"); } chunks.push(part.value); }
    const bytes = Buffer.concat(chunks); let evidence: GatewayAttestationEvidence;
    try { evidence = JSON.parse(bytes.toString("utf8")) as GatewayAttestationEvidence; } catch { throw fail("untrusted"); }
    state.guard();
    let chain: TdxChainVerifier;
    if ("prepare" in options.chainVerifier) {
      chain = await boundedPreparation(prepareSignal => (options.chainVerifier as TdxChainVerifierFactory).prepare(
        typeof evidence.quote === "string" ? evidence.quote : "", {
          acceptedTcbStatuses: policy.acceptableTcbStatuses, nowMs: Date.now(), signal: prepareSignal
        }));
    } else chain = options.chainVerifier;
    state.guard();
    // The SPKI below was read from THIS socket, which fetched the evidence and is
    // the only one that may ever carry content: the one place that can say so.
    const verifySameEvidence = () => verifyGatewayAttestation(evidence, { nonce, origin: origin.origin, policy,
      observedTlsSpkiSha256: state.observedPin, chainVerifier: chain, now: Date.now(),
      observedOnRetainedConnection: true, unqualifiedPlatformPilot: options.unqualifiedPlatformPilot === true });
    let verdict = verifySameEvidence();
    const moved = verdict.status === "failed"
      && verdict.checks.some(check => check.name === "quote_signature_chain" && check.passed)
      && verdict.checks.some(check => !check.passed && ["app_id_pinned", "compose_hash_pinned", "release_pinned", "platform_measurements_pinned", "os_image_pinned", "key_provider_pinned", "release_tuple_matched"].includes(check.name));
    if (moved && options.refreshPolicy) {
      const updated = await boundedPreparation(options.refreshPolicy);
      exact(updated, new Set(["policy", "approvalExpiresAtMs"]));
      if (updated.approvalExpiresAtMs !== undefined && (!Number.isSafeInteger(updated.approvalExpiresAtMs) || updated.approvalExpiresAtMs <= 0)) throw fail("configuration");
      // A refresh replaces approval metadata; it can never make a bounded
      // approval unbounded by simply omitting the expiry.
      if (updated.approvalExpiresAtMs === undefined && approvalExpiry !== Infinity) throw fail("configuration");
      policy = snapshotPolicy(updated.policy); approvalExpiry = updated.approvalExpiresAtMs ?? Infinity;
      state.guard(); verdict = verifySameEvidence();
    }
    if (verdict.status !== "ok" || verdict.verificationLevel !== "hardware-verified" || verdict.tcbStatus !== "UpToDate"
        || !verdict.binding || verdict.binding.tls_spki_sha256 !== state.observedPin
        || !verdict.checks.some(check => check.name === "quote_signature_chain" && check.passed)
        || verdict.checks.some(check => check.required && !check.passed)
        || !Number.isSafeInteger(evidence.issued_at_ms)) {
      const refusal = fail("untrusted");
      refusal.verdict = deepFreeze(verdict);
      throw refusal;
    }
    evidenceExpiry = (evidence.issued_at_ms as number) + policy.maxEvidenceAgeMs;
    if (!Number.isSafeInteger(evidenceExpiry) || evidenceExpiry <= 0) throw fail("untrusted");
    state.authorized = true; state.guard();
    const identity = Object.freeze({ origin: origin.origin, nonce, tlsSpkiSha256: state.observedPin!,
      appId: verdict.binding.app_id, instanceId: verdict.binding.instance_id, composeHash: verdict.binding.compose_hash,
      expiresAtMs: Math.min(evidenceExpiry, approvalExpiry) });
    return Object.freeze({ identity, verdict: deepFreeze(verdict), rawEvidence: deepFreeze(evidence), assertDispatchAllowed: state.guard, fetch: (url: string, init?: RequestInit) => exchange(url, init), close });
  } catch (error) {
    close();
    // Failed preparation cannot start another socket before every local owner
    // and admitted DNS callback has joined. This cannot interrupt OS DNS.
    await agent.joinClosed();
    state.closedJoined = true;
    if (error instanceof RetainedGatewayError && initialConnectionRefusals.get(error) !== state) initialConnectionRefusals.delete(error);
    throw error instanceof RetainedGatewayError ? error : fail("untrusted");
  }
}
