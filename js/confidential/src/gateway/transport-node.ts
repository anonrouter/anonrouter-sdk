// Node-only, opt-in transport preparation. This is a connection primitive,
// not an attestation verifier: install a pin ONLY after independently verifying
// fresh evidence. It is deliberately not exported by the SDK's browser entry.
import { Agent, request, type RequestOptions } from "node:https";
import { connect, checkServerIdentity, type ConnectionOptions, type TLSSocket } from "node:tls";
import { createHash, X509Certificate } from "node:crypto";
import { Readable, type Duplex } from "node:stream";
import { isIP } from "node:net";

export class BoundGatewayTransportError extends Error {
  constructor(readonly code: "configuration" | "tls_pin_mismatch" | "tls_certificate" | "transport" | "cancelled" | "timeout" | "redirect" | "authorization", message: string,
    readonly dispatchPhase: "before_http" | "may_have_dispatched" = "may_have_dispatched") {
    super(message);
    this.name = "BoundGatewayTransportError";
  }
}

export interface BoundGatewayTransportOptions {
  origin: string;
  /** A caller-verified quote's SHA-256 of DER SubjectPublicKeyInfo. This
   * transport does not establish the provenance of the supplied fingerprint. */
  expectedTlsSpkiSha256: string;
  /** Optional explicit trust anchor for self-hosted deployments/tests. Never
   * disables certificate validation. Omit to use Node's normal CA store. */
  ca?: string;
  handshakeTimeoutMs?: number;
  requestTimeoutMs?: number;
  /** Recheck session authorization after TLS, immediately before handing the
   * socket to HTTP. A thrown guard means no HTTP headers/body are dispatched. */
  beforeHttpDispatch?: () => void;
}

export interface BoundGatewayTransport {
  fetch(input: string, init?: RequestInit): Promise<Response>;
  /** Cancels active requests/streams and refuses subsequent use. */
  close(): void;
}

const failure = (code: BoundGatewayTransportError["code"], message: string,
  phase: BoundGatewayTransportError["dispatchPhase"] = "may_have_dispatched") => new BoundGatewayTransportError(code, message, phase);
const configuration = () => failure("configuration", "Unsupported bound gateway transport configuration.", "before_http");
const CERTIFICATE_ERRORS = new Set(["ERR_TLS_CERT_ALTNAME_INVALID", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "CERT_HAS_EXPIRED",
  "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_GET_ISSUER_CERT", "CERT_NOT_YET_VALID", "CERT_REVOKED"]);
const INIT_FIELDS = new Set(["method", "headers", "body", "signal", "credentials", "cache", "redirect"]);
const OPTION_FIELDS = new Set(["origin", "expectedTlsSpkiSha256", "ca", "handshakeTimeoutMs", "requestTimeoutMs", "beforeHttpDispatch"]);

function exactOptions(value: object, fields: Set<string>): void {
  const prototype = Object.getPrototypeOf(value);
  if ((prototype !== Object.prototype && prototype !== null)
      || Reflect.ownKeys(value).some(key => typeof key !== "string" || !fields.has(key))) throw configuration();
}
function deadline(value: number | undefined, fallback: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 3_600_000) throw configuration();
  return result;
}

// HTTP does not receive a socket until PKI, hostname and the attested SPKI have
// all passed. Returning undefined here prevents Agent.createSocket from attaching
// the pending socket (and flushing HTTP headers/body) before our callback.
class BoundAgent extends Agent {
  private readonly handshakes = new Set<TLSSocket>();
  constructor(private readonly hostname: string, private readonly pin: string,
    private readonly trustAnchor: string | undefined, private readonly timeoutMs: number,
    private readonly beforeHttpDispatch: (() => void) | undefined) {
    super({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
  }

  override createConnection(options: ConnectionOptions, callback?: (error: Error | null, socket: Duplex) => void): TLSSocket | undefined {
    if (!callback) throw configuration();
    let settled = false;
    const socket = connect({
      ...options,
      ca: this.trustAnchor,
      rejectUnauthorized: true,
      // A fresh agent and disabled session cache are mandatory. A resumed TLS
      // session may skip the certificate callback; no session is supplied here.
      session: undefined,
      servername: isIP(this.hostname) ? undefined : this.hostname,
      checkServerIdentity: (_host, cert) => checkServerIdentity(this.hostname, cert),
    });
    this.handshakes.add(socket);
    const timer = setTimeout(() => finish(failure("timeout", "Bound gateway TLS handshake timed out.", "before_http")), this.timeoutMs);
    timer.unref();
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      this.handshakes.delete(socket);
      if (error) {
        // No HTTP ownership has been handed out. Destroy without attaching
        // request data, then return a sanitized failure to the HTTP caller.
        socket.destroy();
        callback(error, socket);
      } else callback(null, socket);
    };
    socket.once("error", (error: Error & { code?: string }) => finish(CERTIFICATE_ERRORS.has(error.code ?? "")
      ? failure("tls_certificate", "Bound gateway certificate verification failed.", "before_http")
      : failure("transport", "Bound gateway TLS connection failed.", "before_http")));
    socket.once("close", () => finish(failure("transport", "Bound gateway TLS handshake ended before verification.", "before_http")));
    socket.once("secureConnect", () => {
      try {
        const certificate = socket.getPeerCertificate();
        if (!socket.authorized || !certificate.raw || checkServerIdentity(this.hostname, certificate)) {
          return finish(failure("tls_certificate", "Bound gateway certificate verification failed.", "before_http"));
        }
        const actual = createHash("sha256")
          .update(new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" }))
          .digest("hex");
        if (actual !== this.pin) return finish(failure("tls_pin_mismatch", "Bound gateway TLS key does not match verified evidence.", "before_http"));
      } catch {
        return finish(failure("tls_certificate", "Bound gateway certificate verification failed.", "before_http"));
      }
      try { this.beforeHttpDispatch?.(); }
      catch { return finish(failure("authorization", "Bound gateway authorization no longer permits HTTP dispatch.", "before_http")); }
      finish();
    });
    return undefined;
  }

  override destroy(): void {
    // Node has not received these sockets yet, so the ordinary Agent inventory
    // cannot cancel them. This also bounds abort during an unfinished handshake.
    for (const socket of this.handshakes) socket.destroy();
    this.handshakes.clear();
    super.destroy();
  }
}

export function createSpkiBoundGatewayTransport(options: BoundGatewayTransportOptions): BoundGatewayTransport {
  exactOptions(options, OPTION_FIELDS);
  if (typeof options.origin !== "string" || typeof options.expectedTlsSpkiSha256 !== "string") throw configuration();
  if (options.beforeHttpDispatch !== undefined && typeof options.beforeHttpDispatch !== "function") throw configuration();
  let origin: URL;
  try { origin = new URL(options.origin); } catch { throw configuration(); }
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.search || origin.hash
      || origin.pathname !== "/" || !/^[0-9a-f]{64}$/i.test(options.expectedTlsSpkiSha256)
      || (options.ca !== undefined && (typeof options.ca !== "string" || !options.ca.trim()))) throw configuration();
  const pin = options.expectedTlsSpkiSha256.toLowerCase();
  const handshakeTimeout = deadline(options.handshakeTimeoutMs, 10_000);
  const requestTimeout = deadline(options.requestTimeoutMs, 900_000);
  const trustAnchor = options.ca;
  const beforeHttpDispatch = options.beforeHttpDispatch;
  const pending = new Set<() => void>();
  let closed = false;

  return {
    async fetch(input, init = {}) {
      if (closed) throw failure("cancelled", "Bound gateway transport is closed.");
      exactOptions(init, INIT_FIELDS);
      if (typeof input !== "string" || (init.credentials !== undefined && init.credentials !== "omit")
          || (init.redirect !== undefined && init.redirect !== "error")) throw configuration();
      let target: URL;
      try { target = new URL(input); } catch { throw configuration(); }
      if (target.origin !== origin.origin || target.username || target.password || target.hash) throw configuration();
      const method = (init.method ?? "GET").toUpperCase();
      if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)) throw configuration();
      if ((method === "GET" || method === "HEAD") && init.body != null) throw configuration();
      const headers = new Headers(init.headers);
      headers.forEach((_value, name) => {
        if (["host", "connection", "content-length", "transfer-encoding", "upgrade", "trailer", "expect"].includes(name)
            || name.startsWith("proxy-")) throw configuration();
      });
      // Node HTTPS does not perform fetch's transparent content decompression.
      // Keep this deliberately narrow adapter uncompressed until integration
      // supplies a separately bounded decompression design.
      if (headers.has("accept-encoding") && headers.get("accept-encoding") !== "identity") throw configuration();
      headers.set("accept-encoding", "identity");
      // Copy caller bytes before awaiting anything; mutation cannot replace the
      // request after validation. Streaming upload bodies need a separate design.
      let body: string | Uint8Array | undefined;
      if (init.body != null) {
        if (typeof init.body === "string") body = init.body;
        else if (init.body instanceof Uint8Array) body = Uint8Array.from(init.body);
        else if (init.body instanceof ArrayBuffer) body = new Uint8Array(init.body.slice(0));
        else throw configuration();
      }
      const signal = init.signal;
      if (signal?.aborted) throw failure("cancelled", "Bound gateway request was cancelled.");
      // Exactly one new, private agent for each request. Concurrent A/B operations
      // never alter one another's pin; generic/global agents cannot enter here.
      const hostname = target.hostname.replace(/^\[|\]$/g, "");
      const agent = new BoundAgent(hostname, pin, trustAnchor, handshakeTimeout, beforeHttpDispatch);
      const requestHeaders: Record<string, string> = {};
      headers.forEach((value, name) => { requestHeaders[name] = value; });
      return await new Promise<Response>((resolve, reject) => {
        let done = false;
        let requestStarted = false;
        let httpSocketAccepted = false;
        const cleanup = () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          signal?.removeEventListener("abort", abort);
          pending.delete(closeRequest);
          agent.destroy();
        };
        const phase = (): BoundGatewayTransportError["dispatchPhase"] => httpSocketAccepted ? "may_have_dispatched" : "before_http";
        const abort = () => terminate(failure("cancelled", "Bound gateway request was cancelled.", phase()));
        const closeRequest = () => terminate(failure("cancelled", "Bound gateway transport was closed.", phase()));
        const terminate = (error: BoundGatewayTransportError) => {
          if (done) return;
          if (requestStarted) req.destroy(error);
          reject(error);
          cleanup();
        };
        const timer = setTimeout(() => terminate(failure("timeout", "Bound gateway request timed out.", phase())), requestTimeout);
        timer.unref();
        const req = request({
          protocol: "https:", hostname, port: target.port || 443,
          path: target.pathname + target.search, method,
          headers: requestHeaders, agent,
        } satisfies RequestOptions, response => {
          const status = response.statusCode ?? 0;
          if (status >= 300 && status < 400 && status !== 304) {
            response.destroy();
            terminate(failure("redirect", "Bound gateway transport refuses redirects."));
            return;
          }
          if (response.headers["content-encoding"] !== undefined && response.headers["content-encoding"] !== "identity") {
            response.destroy();
            terminate(failure("transport", "Bound gateway response uses unsupported content encoding."));
            return;
          }
          const responseHeaders = new Headers();
          for (let index = 0; index < response.rawHeaders.length; index += 2) {
            responseHeaders.append(response.rawHeaders[index]!, response.rawHeaders[index + 1]!);
          }
          response.once("end", cleanup);
          response.once("close", cleanup);
          // Backpressure and body cancellation are carried through the native
          // Web stream bridge. Keep abort/deadline hooks until body completion.
          const bodyless = method === "HEAD" || [204, 205, 304].includes(status);
          const stream = bodyless ? null : Readable.toWeb(response) as ReadableStream<Uint8Array>;
          if (bodyless) response.resume();
          try { resolve(new Response(stream, { status, statusText: response.statusMessage, headers: responseHeaders })); }
          catch { terminate(failure("transport", "Bound gateway response could not be represented.")); }
        });
        requestStarted = true;
        req.once("socket", () => { httpSocketAccepted = true; });
        req.once("error", error => {
          reject(error instanceof BoundGatewayTransportError ? error : failure("transport", "Bound gateway request failed.", phase()));
          cleanup();
        });
        pending.add(closeRequest);
        signal?.addEventListener("abort", abort, { once: true });
        // Recheck after listener registration to close the cancellation race.
        if (closed || signal?.aborted) return terminate(failure("cancelled", "Bound gateway request was cancelled."));
        req.end(body);
      });
    },
    close() {
      if (closed) return;
      closed = true;
      for (const cancel of [...pending]) cancel();
    },
  };
}
