// The AnonRouter confidential client. It ties the pure verifier core to the live
// AnonRouter API so a developer can, from their own Node/browser app:
//   - verifyGateway():     independently verify HOP 1, AnonRouter's own
//     confidential routing plane, against locally pinned measurements;
//   - verifyAttestation(): independently verify HOP 2, the downstream provider
//     route, running OUR verifier on the RAW evidence (never just trusting the
//     gateway's verdict);
//   - verify():            both hops in one call, with one honest verdict; and
//   - chat():              run confidential (E2EE) inference end to end.
//
// The two hops answer different questions and neither implies the other:
//
//   HOP 1  Is the AnonRouter data plane I am connected to the exact reviewed
//          build, running inside an Intel TDX confidential VM, bound to my nonce
//          and my origin? (GET /v1/gateway/attestation)
//   HOP 2  Did the model provider terminate my request inside a verified enclave
//          running measurements I pinned? (/v1/tee/attestation)
//
// A verified hop 2 says nothing about who routed the request, and a verified hop 1
// says nothing about where inference actually ran. Only asking both establishes
// the whole path, which is why verify() reports them separately and never
// collapses them into a single reassuring boolean without saying what it covers.
//
// The chat() flow strictly enforces the security contract:
//   attestation ticket (Bearer) -> attestation (ticket header, NO creds) ->
//   GATE on the gateway verdict AND our own independent raw-evidence checks ->
//   inference ticket (Bearer, e2ee:true) -> encrypt -> relay ciphertext -> decrypt.
// Every run uses fresh keys and a fresh nonce; key material is disposed in finally.
// Plaintext is never sent to the relay.

import { bytesToHex, randomBytes } from "./bytes.js";
import { ConfidentialError } from "./errors.js";
import { enableNodeCrypto, hexEqual } from "./verify/crypto.js";
import { verifyRawEvidence } from "./verify/index.js";
import type { NormalizedVerdict, PrivacyModality, VerificationLevel } from "./verify/types.js";
import {
  assembleRouteVerdict,
  gatewayHopVerdict,
  hopNotRequested,
  hopUnavailable,
  providerHopVerdict,
  type RouteVerdict
} from "./verify/route.js";
import { GATEWAY_NONCE_HEX_LENGTH } from "./gateway/binding.js";
import {
  pinnedGatewayPolicyFor,
  type GatewayMeasurementPolicy,
  type GatewayPolicyStatus
} from "./gateway/policy.js";
import {
  verifyGatewayAttestation,
  type GatewayAttestationEvidence,
  type GatewayVerificationResult,
  type TdxChainVerifier
} from "./gateway/verify.js";
import { transportFor } from "./transport/index.js";
import { validateE2eeMessages, validateE2eeRequest, type RawTurnMessage } from "./transport/validation.js";
import { joinUrl, type FetchLike, type HttpContext } from "./transport/types.js";

export interface CreateClientOptions {
  /** AnonRouter API origin, e.g. "https://api.anonrouter.ai". Must be an origin
   *  (scheme + host + optional port), not a path, and must be https unless the
   *  host is loopback and `allowInsecureHttp` is set. */
  baseUrl: string;
  /** Your AnonRouter API key. Sent as `Authorization: Bearer <apiKey>` on the
   *  authenticated control requests only, never to the credential-isolated relay. */
  apiKey: string;
  /** Optional fetch implementation (defaults to globalThis.fetch). */
  fetch?: FetchLike;
  /**
   * Permit a plaintext http:// baseUrl against a loopback host, for local
   * development against a gateway on your own machine. Never accepted for a
   * non-loopback host: over plaintext http the API key travels in the clear and
   * the origin a gateway quote binds cannot mean anything, so allowing it for a
   * remote host would turn an attested route into a decorative one.
   */
  allowInsecureHttp?: boolean;
}

/** Loopback hosts, where plaintext http can be opted into for local development. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/**
 * Normalize and validate the API origin.
 *
 * The origin is security-relevant in its own right: a gateway quote binds the
 * exact origin the client connected to, so a baseUrl carrying a path, a query, or
 * credentials could not be compared against it, and a plaintext one could not be
 * trusted to have reached the host at all. Trailing slashes are tolerated and
 * stripped because they are a habit, not an ambiguity.
 */
function normalizeApiOrigin(baseUrl: unknown, allowInsecureHttp: boolean): string {
  if (typeof baseUrl !== "string" || baseUrl.length === 0) {
    throw new ConfidentialError("unsupported_request", "createClient needs a baseUrl.");
  }
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new ConfidentialError("unsupported_request", "The baseUrl must be an absolute URL, for example https://api.anonrouter.ai.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new ConfidentialError("unsupported_request", "The baseUrl must be a bare origin: no credentials, query, or fragment.");
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") {
    throw new ConfidentialError("unsupported_request", "The baseUrl must be a bare origin with no path, for example https://api.anonrouter.ai (not .../v1).");
  }
  if (parsed.protocol === "http:") {
    if (!allowInsecureHttp || !LOOPBACK_HOSTS.has(parsed.hostname)) {
      throw new ConfidentialError(
        "unsupported_request",
        "The baseUrl must be https. Plaintext http is accepted only for a loopback host, and only with allowInsecureHttp: true."
      );
    }
  } else if (parsed.protocol !== "https:") {
    throw new ConfidentialError("unsupported_request", "The baseUrl scheme must be https.");
  }
  return parsed.origin;
}

export interface VerifyAttestationInput {
  model: string;
  provider: string;
  /** Optional caller nonce (hex, 32..128 chars). A fresh one is generated if omitted. */
  nonce?: string;
  /** The provider-native model id the evidence is expected to attest, when you
   *  already know it. Enclaves name themselves in provider terms (for example
   *  "e2ee-gpt-oss-20b-p"), not by AnonRouter's catalog id, so the model binding
   *  has to be checked against the provider-native name.
   *
   *  Normally you do not set this: the gateway reports the mapping as
   *  `upstream_model` and the SDK uses it. Set it to pin the binding yourself, or
   *  when talking to a gateway old enough not to report the field (without it,
   *  such a gateway leaves the SDK binding against the catalog id, which shows up
   *  as a `model_binding` failure on otherwise valid evidence). An explicit value
   *  always wins over whatever the gateway says. */
  upstreamModel?: string;
  signal?: AbortSignal;
}

export interface VerifyAttestationResult {
  provider: string;
  model: string;
  /** The provider-native model id the evidence was bound against. */
  upstreamModel: string;
  privacyModality: PrivacyModality;
  /** OUR independent verification of the raw evidence. Authoritative. */
  verdict: NormalizedVerdict;
  /** What the gateway returned. Never trusted by itself. */
  gatewayVerdict?: NormalizedVerdict;
  /** The raw provider evidence, returned verbatim for further independent checks. */
  rawEvidence: unknown;
}

// ---- Hop 1: AnonRouter's own confidential routing plane ----------------------

export interface VerifyGatewayInput {
  /** Optional caller nonce (exactly 64 hex chars). A fresh one is generated if omitted. */
  nonce?: string;
  /**
   * The locally pinned policy to hold the plane to. Defaults to the pin this
   * package ships for the client's origin. Supply your own to pin a release you
   * reviewed yourself, or to verify a plane this package does not ship a pin for.
   */
  policy?: GatewayMeasurementPolicy;
  /**
   * Accept a shipped pin whose status is `candidate` (a reviewed but pre-release
   * plane whose measurements are expected to move). Off by default, so a default
   * call can never quietly pass against a plane the operator has not released.
   */
  allowCandidatePolicy?: boolean;
  /**
   * SHA-256 of the DER SubjectPublicKeyInfo of the certificate your TLS session
   * actually used, when your runtime can observe it. This is what proves the
   * attested TD owns the very connection carrying your request. A browser cannot
   * see it; leave it undefined there and the check is recorded as an unmet gap
   * rather than assumed away.
   */
  observedTlsSpkiSha256?: string | null;
  /**
   * A DCAP engine that chains the quote's ECDSA signature to Intel's roots. This
   * package ships none, so without one the honest ceiling is `provider-attested`
   * and a policy with `requireHardwareVerified` fails closed.
   */
  chainVerifier?: TdxChainVerifier;
  signal?: AbortSignal;
}

/** Where the policy used for a gateway verdict came from. */
export interface GatewayPolicyProvenance {
  origin: "caller-supplied" | "package-pinned";
  source: string;
  version: string;
  /** Only set for a package-pinned policy. */
  status?: GatewayPolicyStatus;
}

export interface VerifyGatewayResult {
  /** The exact origin this client connected to and bound the quote against. */
  origin: string;
  policy: GatewayPolicyProvenance;
  /** OUR independent verification of the raw evidence. Authoritative. */
  verdict: GatewayVerificationResult;
  /** The raw gateway evidence, returned verbatim for further independent checks. */
  rawEvidence: GatewayAttestationEvidence;
}

// ---- Both hops in one call ---------------------------------------------------

/** Ask verify() to establish hop 1 as well. `false` skips it entirely. */
export type VerifyGatewayOption = boolean | Omit<VerifyGatewayInput, "signal">;

export interface VerifyInput {
  model: string;
  provider: string;
  /** See VerifyAttestationInput.upstreamModel. */
  upstreamModel?: string;
  /** Optional caller nonce for the provider hop (hex, 32..128 chars). */
  nonce?: string;
  /**
   * Whether to also establish hop 1, AnonRouter's own confidential plane.
   * Defaults to false: most deployments do not run inside a CVM yet, and a
   * report that silently skipped a hop must never read as if it covered one.
   * `report.gateway.requested` always says which way this went.
   */
  gateway?: VerifyGatewayOption;
  signal?: AbortSignal;
}

/**
 * Hop 1's outcome.
 *
 *   not-requested  this call never asked about AnonRouter's own plane
 *   unavailable    the deployment does not expose gateway attestation at all
 *   unpinned       no policy: neither supplied nor shipped for this origin
 *   failed         evidence was returned and did NOT verify
 *   ok             verified against the pinned policy
 */
export interface GatewayHopReport {
  requested: boolean;
  status: "ok" | "failed" | "unavailable" | "unpinned" | "not-requested";
  verificationLevel: VerificationLevel | null;
  reason: string | null;
  policy?: GatewayPolicyProvenance;
  verdict?: GatewayVerificationResult;
  rawEvidence?: GatewayAttestationEvidence;
}

/** Hop 2's outcome: the downstream provider route. Always attempted. */
export interface ProviderHopReport {
  status: "ok" | "failed";
  verificationLevel: VerificationLevel;
  reason: string | null;
  /** OUR independent verdict over the raw evidence. Authoritative. */
  verdict: NormalizedVerdict;
  /** What the gateway returned. Never trusted by itself. */
  gatewayVerdict?: NormalizedVerdict;
  rawEvidence: unknown;
}

export interface VerificationReport {
  route: {
    provider: string;
    model: string;
    upstreamModel: string;
    privacyModality: PrivacyModality;
    /**
     * True on a `tee` route: execution ran in a verified enclave, but AnonRouter's
     * gateway still sees your plaintext to route and meter it. Only an `e2ee`
     * route keeps content opaque to AnonRouter. This is the single most
     * misunderstood fact about TEE routing, so it is stated as a fact and not
     * left to be inferred from a modality string.
     */
    contentVisibleToAnonRouter: boolean;
  };
  /** Hop 1: AnonRouter's own confidential routing plane. */
  gateway: GatewayHopReport;
  /** Hop 2: the downstream provider route. */
  provider: ProviderHopReport;
  /**
   * True when every hop this call was ASKED to establish verified. Read
   * `gateway.requested` to know whether that included hop 1: a report with
   * `trusted: true` and `gateway.requested: false` establishes the provider
   * enclave and says nothing at all about who routed the request.
   */
  trusted: boolean;
  /** The first unmet requirement, or null. Sanitized and content-free. */
  reason: string | null;
}

export interface ChatInput {
  model: string;
  provider: string;
  messages: RawTurnMessage[];
  maxOutputTokens: number;
  /**
   * Establish hop 1 before sending anything, and FAIL CLOSED if it does not
   * verify. Off by default because most deployments do not run inside a CVM yet;
   * set it wherever you require AnonRouter's own plane to be attested, not just
   * the provider's.
   */
  requireGateway?: VerifyGatewayOption;
  signal?: AbortSignal;
  onDelta?: (delta: { content?: string; reasoning?: string }) => void;
}

export interface ChatResult {
  content: string;
  reasoning?: string;
  usage?: { promptTokens?: number; completionTokens?: number; totalTokens?: number };
}

export interface AnonRouterClient {
  /**
   * THE STABLE CONTRACT. Both hops, cross-bound to one route, reported as
   * ordered states. This is the call to build on; the shape of `RouteVerdict` is
   * what this SDK promises to keep.
   */
  verifyRoute(input: VerifyRouteInput): Promise<RouteVerdict>;
  /** Hop 1: independently verify AnonRouter's own confidential routing plane. */
  verifyGateway(input?: VerifyGatewayInput): Promise<VerifyGatewayResult>;
  /** Hop 2: independently verify the downstream provider route. */
  verifyAttestation(input: VerifyAttestationInput): Promise<VerifyAttestationResult>;
  /** Both hops in the earlier report shape. Prefer `verifyRoute`. */
  verify(input: VerifyInput): Promise<VerificationReport>;
  chat(input: ChatInput): Promise<ChatResult>;
}

export interface VerifyRouteInput {
  model: string;
  provider: string;
  /** Optional caller nonce for the provider hop (hex, 32..128 chars). */
  nonce?: string;
  /**
   * Pin the provider-native model id the evidence must attest. When set, a
   * disagreement with what the evidence actually attests is reported as a route
   * binding mismatch rather than silently accepted.
   */
  upstreamModel?: string;
  /**
   * Establish hop 1 as well. Defaults to false, because most deployments do not
   * run inside a CVM and a verdict must never imply a hop it skipped. The
   * resulting `gateway.requested` always says which way this went.
   */
  gateway?: VerifyGatewayOption;
  signal?: AbortSignal;
}

const ACCEPTED_LEVELS = new Set<VerificationLevel>(["provider-attested", "sdk-verified", "hardware-verified"]);

function privacyModalityFor(provider: string): PrivacyModality {
  return provider === "tinfoil" ? "tee" : "e2ee";
}

function freshNonce(): string {
  return bytesToHex(randomBytes(32));
}

/** Normalize the `gateway` / `requireGateway` option into explicit inputs. */
function gatewayOptionToInput(option: VerifyGatewayOption | undefined): Omit<VerifyGatewayInput, "signal"> | null {
  if (option === undefined || option === false) return null;
  return option === true ? {} : option;
}

/** Coerce a gateway `attestation` object (already snake_case) into a
 *  NormalizedVerdict, filling defaults so a partial/legacy shape still parses. */
function coerceGatewayVerdict(raw: unknown): NormalizedVerdict | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Partial<NormalizedVerdict>;
  if (typeof r.status !== "string" || typeof r.verification_level !== "string") return undefined;
  return {
    status: r.status,
    verification_level: r.verification_level,
    privacy_modality: r.privacy_modality ?? "e2ee",
    hardware_type: r.hardware_type ?? "unknown",
    measurement_identities: r.measurement_identities ?? {},
    model_weight_identity: r.model_weight_identity ?? null,
    attested_tls_spki: r.attested_tls_spki ?? null,
    attested_encryption_key: r.attested_encryption_key ?? null,
    attested_signing_key: r.attested_signing_key ?? null,
    nonce: r.nonce ?? null,
    verified_at: r.verified_at ?? new Date(0).toISOString(),
    expires_at: r.expires_at ?? new Date(0).toISOString(),
    policy_source: r.policy_source ?? null,
    verifier_version: r.verifier_version ?? "gateway",
    supports_client_opaque_e2ee: Boolean(r.supports_client_opaque_e2ee),
    reason: r.reason ?? null,
    checks: Array.isArray(r.checks) ? r.checks : []
  };
}

/** Fail closed unless the gateway verdict is a successful, e2ee, client-opaque
 *  result bound to our exact fresh nonce. This is a cross-check; it never replaces
 *  our own independent raw-evidence gate (the transport's createSession). */
function gateGatewayVerdict(verdict: NormalizedVerdict | undefined, nonce: string): void {
  if (!verdict) throw new ConfidentialError("attestation_untrusted", "The gateway did not return a verification result.");
  if (verdict.status !== "ok") {
    throw new ConfidentialError(
      "attestation_untrusted",
      `The enclave attestation did not verify (gateway verdict: ${verdict.status}/${verdict.verification_level}, reason: ${verdict.reason ?? "unknown"}). Run the verify-tee example for this provider to see the failing checks.`
    );
  }
  if (verdict.privacy_modality !== "e2ee") throw new ConfidentialError("attestation_untrusted", "The attested route is not client-opaque E2EE.");
  if (!verdict.supports_client_opaque_e2ee) throw new ConfidentialError("attestation_untrusted", "The attested route does not support client encryption.");
  if (!ACCEPTED_LEVELS.has(verdict.verification_level)) throw new ConfidentialError("attestation_untrusted", "The enclave verification level is not acceptable.");
  if (!hexEqual(verdict.nonce, nonce)) throw new ConfidentialError("nonce_mismatch", "The attestation was not bound to this request's nonce.");
}

interface AttestationResponse {
  evidence: unknown;
  provider?: string;
  upstream_model?: string;
  /** "tee" or "e2ee": what the gateway says this route is. Cross-checked, never trusted. */
  privacy_class?: string;
  protocol?: string;
  attestation?: unknown;
}

export function createClient(options: CreateClientOptions): AnonRouterClient {
  const origin = normalizeApiOrigin(options.baseUrl, options.allowInsecureHttp === true);
  if (typeof options.apiKey !== "string" || options.apiKey.length === 0) {
    throw new ConfidentialError("unsupported_request", "createClient needs an apiKey.");
  }
  const fetchImpl: FetchLike = options.fetch ?? (globalThis.fetch.bind(globalThis) as FetchLike);
  const authHeaders = { authorization: `Bearer ${options.apiKey}` };
  const http: HttpContext = { baseUrl: origin, fetchImpl };

  /**
   * Fetch raw attestation evidence for a route, for verification only.
   *
   * Two paths exist, and which one is reachable depends on how AnonRouter is
   * deployed, so this tries them in the order that works most widely:
   *
   *  1. Ticketed: mint a content-free attestation ticket, then present ONLY that
   *     ticket to the attestation endpoint. Where attestation is served by the
   *     credential-isolated relay, this is the only path that works: a request
   *     carrying an account key is refused there, by design, because that relay
   *     never accepts account credentials alongside a route it serves. This path
   *     also reports `upstream_model`, which the model binding needs.
   *  2. Key-authenticated GET, for a deployment that serves this route directly.
   *     Attestation tickets are only issued for E2EE-capable models, so this is
   *     also the only path that can verify a TEE-only route such as Tinfoil.
   *
   * Neither path ever carries content, and attestation is not a billable
   * inference call.
   */
  async function fetchAttestationEvidence(
    model: string,
    provider: string,
    nonce: string,
    signal?: AbortSignal
  ): Promise<AttestationResponse> {
    const parse = async (response: Response): Promise<AttestationResponse> => {
      let body: AttestationResponse;
      try {
        body = (await response.json()) as AttestationResponse;
      } catch {
        throw new ConfidentialError("evidence_invalid", "The attestation response could not be parsed.");
      }
      if (!body || typeof body !== "object" || !("evidence" in body)) {
        throw new ConfidentialError("evidence_invalid", "The attestation response did not contain evidence.");
      }
      return body;
    };

    let ticket: string | null = null;
    try {
      const issued = await postJson<{ ticket?: unknown }>(
        "/v1/inference/attestation-tickets",
        { model, provider },
        signal,
        "attestation_ticket_failed"
      );
      ticket = typeof issued.ticket === "string" && issued.ticket.length > 0 ? issued.ticket : null;
    } catch (cause) {
      // A TEE-only route cannot be issued an attestation ticket. Fall through to
      // the key-authenticated path rather than reporting it as a hard failure.
      if (cause instanceof ConfidentialError && cause.code === "cancelled") throw cause;
      ticket = null;
    }

    if (ticket) {
      let response: Response;
      try {
        response = await fetchImpl(joinUrl(origin, "/v1/tee/attestation"), {
          method: "POST",
          credentials: "omit",
          cache: "no-store",
          headers: { "content-type": "application/json", "x-anonrouter-ticket": ticket },
          body: JSON.stringify({ nonce }),
          signal
        });
      } catch {
        if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
        throw new ConfidentialError("attestation_failed", "Could not reach the attestation relay.");
      }
      if (response.ok) return parse(response);
      // Fall through only on a routing/authorization mismatch; a genuine
      // attestation failure should surface as itself.
      if (response.status !== 401 && response.status !== 404) {
        throw new ConfidentialError("attestation_failed", `Attestation failed with status ${response.status}.`);
      }
    }

    const url = `${joinUrl(origin, "/v1/tee/attestation")}?`
      + new URLSearchParams({ model, provider, nonce }).toString();
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "GET",
        cache: "no-store",
        headers: { accept: "application/json", ...authHeaders },
        signal
      });
    } catch {
      if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError("attestation_failed", "Could not reach the attestation service.");
    }
    if (response.ok) return parse(response);
    if (response.status === 401 && !ticket) {
      throw new ConfidentialError(
        "attestation_failed",
        `This deployment serves attestation only through the credential-isolated relay, which takes a single-use ticket, and ${provider}/${model} was not issued one. Attestation tickets are issued for E2EE-capable routes; a TEE-only route cannot be verified against this host.`
      );
    }
    throw new ConfidentialError("attestation_failed", `Attestation request failed with status ${response.status}.`);
  }

  async function verifyAttestation(input: VerifyAttestationInput): Promise<VerifyAttestationResult> {
    const provider = input.provider;
    const model = input.model;
    const nonce = input.nonce ?? freshNonce();
    if (!/^[0-9a-f]{32,128}$/i.test(nonce)) {
      throw new ConfidentialError("unsupported_request", "The attestation nonce must be 32..128 hex characters.");
    }
    // Make the Node X.509 possession check available (no-op / degrade in a browser).
    await enableNodeCrypto();

    const body = await fetchAttestationEvidence(model, provider, nonce, input.signal);

    // Bind the route the gateway actually served. Substituted evidence would fail
    // the verifier's own parse anyway, but failing here names the real problem
    // (AnonRouter routed elsewhere) instead of surfacing it as malformed evidence.
    if (typeof body.provider === "string" && body.provider !== provider) {
      throw new ConfidentialError("attestation_untrusted", "The attestation was bound to a different provider than the one requested.");
    }
    // A route the gateway itself labels `tee` cannot carry client-opaque E2EE, so
    // verifying it under an e2ee expectation would be checking the wrong contract.
    if (typeof body.privacy_class === "string"
      && body.privacy_class !== privacyModalityFor(provider)
      && (body.privacy_class === "tee" || body.privacy_class === "e2ee")) {
      throw new ConfidentialError(
        "attestation_untrusted",
        `The gateway served a ${body.privacy_class} route for ${provider}, which is not the privacy modality this SDK verifies for that provider.`
      );
    }

    // Precedence: what the caller pinned, then what the gateway reports, then the
    // catalog id as a last resort. The last resort is only correct when the two ids
    // coincide; when they do not, the model binding fails closed rather than
    // silently binding to the wrong name.
    const upstreamModel = typeof input.upstreamModel === "string" && input.upstreamModel.length > 0
      ? input.upstreamModel
      : typeof body.upstream_model === "string" && body.upstream_model.length > 0
        ? body.upstream_model
        : model;
    const privacyModality = privacyModalityFor(provider);
    const gatewayVerdict = coerceGatewayVerdict(body.attestation);

    // Our independent verdict over the RAW evidence. This is authoritative.
    const verdict = verifyRawEvidence(provider, body.evidence, {
      upstreamModel,
      canonicalModel: model,
      nonce,
      privacyModality
    });

    return { provider, model, upstreamModel, privacyModality, verdict, gatewayVerdict, rawEvidence: body.evidence };
  }

  // ---- Hop 1: AnonRouter's own confidential routing plane --------------------

  /**
   * Resolve the policy to hold the plane to, and say where it came from.
   *
   * A caller-supplied policy always wins. Otherwise the pin this package ships
   * for THIS client's origin is used. There is deliberately no path that fetches
   * a policy from the gateway: a server that could hand a client the list of
   * builds the client accepts could always name itself.
   */
  function resolveGatewayPolicy(
    input: Omit<VerifyGatewayInput, "signal">
  ): { policy: GatewayMeasurementPolicy; provenance: GatewayPolicyProvenance } | null {
    if (input.policy) {
      return {
        policy: input.policy,
        provenance: { origin: "caller-supplied", source: input.policy.source, version: input.policy.version }
      };
    }
    const entry = pinnedGatewayPolicyFor(origin, { allowCandidate: input.allowCandidatePolicy === true });
    if (!entry) return null;
    return {
      policy: entry.policy,
      provenance: {
        origin: "package-pinned",
        source: entry.policy.source,
        version: entry.policy.version,
        status: entry.status
      }
    };
  }

  /** Sentinel for "this deployment does not expose gateway attestation at all". */
  const GATEWAY_UNAVAILABLE = Symbol("gateway_unavailable");

  /**
   * Fetch the gateway attestation document. Credential-free by design: a client
   * verifies the plane BEFORE it trusts the endpoint with anything, so sending a
   * key here would invert the trust order.
   */
  async function fetchGatewayEvidence(
    nonce: string,
    signal?: AbortSignal
  ): Promise<GatewayAttestationEvidence | typeof GATEWAY_UNAVAILABLE> {
    const url = `${joinUrl(origin, "/v1/gateway/attestation")}?${new URLSearchParams({ nonce }).toString()}`;
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        headers: { accept: "application/json" },
        signal
      });
    } catch {
      if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError("attestation_failed", "Could not reach the gateway attestation service.");
    }
    // 503 is the documented answer from a deployment that is not running inside an
    // attestable CVM; 404 is a gateway too old to serve the route. Both mean "this
    // hop cannot be established here", which is different from "it failed".
    if (response.status === 503 || response.status === 404) return GATEWAY_UNAVAILABLE;
    if (!response.ok) {
      throw new ConfidentialError("attestation_failed", `Gateway attestation failed with status ${response.status}.`);
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new ConfidentialError("evidence_invalid", "The gateway attestation response could not be parsed.");
    }
    if (!body || typeof body !== "object" || !("binding" in body) || !("quote" in body)) {
      throw new ConfidentialError("evidence_invalid", "The gateway attestation response did not contain a binding and a quote.");
    }
    return body as GatewayAttestationEvidence;
  }

  async function verifyGateway(input: VerifyGatewayInput = {}): Promise<VerifyGatewayResult> {
    const nonce = (input.nonce ?? freshNonce()).toLowerCase();
    if (nonce.length !== GATEWAY_NONCE_HEX_LENGTH || !/^[0-9a-f]+$/.test(nonce)) {
      throw new ConfidentialError(
        "unsupported_request",
        `The gateway attestation nonce must be exactly ${GATEWAY_NONCE_HEX_LENGTH} hex characters.`
      );
    }
    const resolved = resolveGatewayPolicy(input);
    if (!resolved) {
      // No policy means nothing to check the evidence against. Fetching it anyway
      // and reporting what it says would be reading the claim back to the caller.
      throw new ConfidentialError(
        "measurement_untrusted",
        `No pinned gateway policy for ${origin}. Supply one via the policy option, or pass allowCandidatePolicy: true if this package ships a pre-release pin for this origin.`
      );
    }
    const evidence = await fetchGatewayEvidence(nonce, input.signal);
    if (evidence === GATEWAY_UNAVAILABLE) {
      throw new ConfidentialError(
        "attestation_failed",
        `${origin} does not expose gateway attestation, so it cannot be shown to run inside a confidential VM.`
      );
    }
    const verdict = verifyGatewayAttestation(evidence, {
      nonce,
      origin,
      policy: resolved.policy,
      now: Date.now(),
      observedTlsSpkiSha256: input.observedTlsSpkiSha256,
      chainVerifier: input.chainVerifier
    });
    return { origin, policy: resolved.provenance, verdict, rawEvidence: evidence };
  }

  /**
   * Establish hop 1 for verify()/chat(), turning every outcome into a report
   * rather than an exception, so the caller decides what a given status means.
   */
  async function gatewayHop(
    option: Omit<VerifyGatewayInput, "signal">,
    signal?: AbortSignal
  ): Promise<GatewayHopReport> {
    const resolved = resolveGatewayPolicy(option);
    if (!resolved) {
      return {
        requested: true,
        status: "unpinned",
        verificationLevel: null,
        reason: `no pinned gateway policy for ${origin}`
      };
    }
    const nonce = (option.nonce ?? freshNonce()).toLowerCase();
    const evidence = await fetchGatewayEvidence(nonce, signal);
    if (evidence === GATEWAY_UNAVAILABLE) {
      return {
        requested: true,
        status: "unavailable",
        verificationLevel: null,
        reason: "this deployment does not expose gateway attestation",
        policy: resolved.provenance
      };
    }
    const verdict = verifyGatewayAttestation(evidence, {
      nonce,
      origin,
      policy: resolved.policy,
      now: Date.now(),
      observedTlsSpkiSha256: option.observedTlsSpkiSha256,
      chainVerifier: option.chainVerifier
    });
    return {
      requested: true,
      status: verdict.status === "ok" ? "ok" : "failed",
      verificationLevel: verdict.verificationLevel,
      reason: verdict.reason,
      policy: resolved.provenance,
      verdict,
      rawEvidence: evidence
    };
  }

  // ---- Both hops ------------------------------------------------------------

  async function verify(input: VerifyInput): Promise<VerificationReport> {
    const gatewayOption = gatewayOptionToInput(input.gateway);
    const gateway: GatewayHopReport = gatewayOption === null
      ? { requested: false, status: "not-requested", verificationLevel: null, reason: null }
      : await gatewayHop(gatewayOption, input.signal);

    const attestation = await verifyAttestation({
      model: input.model,
      provider: input.provider,
      upstreamModel: input.upstreamModel,
      nonce: input.nonce,
      signal: input.signal
    });

    const provider: ProviderHopReport = {
      status: attestation.verdict.status,
      verificationLevel: attestation.verdict.verification_level,
      reason: attestation.verdict.reason,
      verdict: attestation.verdict,
      gatewayVerdict: attestation.gatewayVerdict,
      rawEvidence: attestation.rawEvidence
    };

    const gatewayTrusted = !gateway.requested || gateway.status === "ok";
    const trusted = gatewayTrusted && provider.status === "ok";
    const reason = !gatewayTrusted
      ? `gateway: ${gateway.reason ?? gateway.status}`
      : provider.status === "ok"
        ? null
        : `provider: ${provider.reason ?? "verification_failed"}`;

    return {
      route: {
        provider: attestation.provider,
        model: attestation.model,
        upstreamModel: attestation.upstreamModel,
        privacyModality: attestation.privacyModality,
        contentVisibleToAnonRouter: attestation.privacyModality === "tee"
      },
      gateway,
      provider,
      trusted,
      reason
    };
  }

  /**
   * THE STABLE CONTRACT. Establish the route end to end and report what actually
   * held, as ordered states rather than as a single boolean.
   *
   * The provider hop always runs. The gateway hop runs only when asked, and the
   * verdict says which way that went, so a caller can never mistake a skipped
   * hop for a passing one. Any disagreement between the requested route and what
   * a hop attested forces the whole verdict untrusted, however strong the
   * individual hops were.
   */
  async function verifyRoute(input: VerifyRouteInput): Promise<RouteVerdict> {
    const gatewayOption = gatewayOptionToInput(input.gateway);
    const privacyModality = privacyModalityFor(input.provider);

    let gatewayHop = gatewayOption === null ? hopNotRequested() : null;
    if (gatewayOption !== null) {
      const hop = await gatewayHop2(gatewayOption, input.signal);
      gatewayHop = hop.verdict;
    }

    // The provider hop can throw on a route-binding refusal (the gateway served
    // a different provider or privacy class). That is a mismatch, not a crash,
    // so it is turned back into a verdict the caller can read.
    let attestation: VerifyAttestationResult | null = null;
    let providerFailure: string | null = null;
    try {
      attestation = await verifyAttestation({
        model: input.model,
        provider: input.provider,
        upstreamModel: input.upstreamModel,
        nonce: input.nonce,
        signal: input.signal
      });
    } catch (error) {
      if (error instanceof ConfidentialError && error.code === "cancelled") throw error;
      providerFailure = error instanceof ConfidentialError ? error.code : "provider_verification_failed";
    }

    const providerHop = attestation
      ? providerHopVerdict(attestation.verdict)
      : hopFromFailure(providerFailure ?? "provider_verification_failed");

    return assembleRouteVerdict({
      route: { provider: input.provider, model: input.model, privacyModality },
      gateway: gatewayHop ?? hopNotRequested(),
      provider: providerHop,
      gatewayEcho: attestation
        ? { provider: attestation.provider, privacyClass: attestation.privacyModality }
        : undefined,
      attestedUpstreamModel: attestation?.upstreamModel ?? null,
      expectedUpstreamModel: input.upstreamModel ?? null
    });
  }

  /** A provider hop that could not produce a verdict at all. */
  function hopFromFailure(reason: string) {
    return {
      requested: true,
      state: "untrusted" as const,
      meaning: "A required check failed. Do not proceed on this route.",
      reason,
      failedChecks: [reason],
      advisoryGaps: []
    };
  }

  /** gatewayHop, wrapped so verifyRoute gets the stable hop shape. */
  async function gatewayHop2(
    option: Omit<VerifyGatewayInput, "signal">,
    signal?: AbortSignal
  ): Promise<{ verdict: ReturnType<typeof gatewayHopVerdict> }> {
    const report = await gatewayHop(option, signal);
    if (report.status === "unavailable" || report.status === "unpinned") {
      return { verdict: hopUnavailable(report.reason ?? report.status) };
    }
    if (!report.verdict) {
      return { verdict: hopUnavailable(report.reason ?? "no gateway verdict") };
    }
    return { verdict: gatewayHopVerdict(report.verdict) };
  }

  async function postJson<T>(path: string, payload: unknown, signal?: AbortSignal, failCode: ConfidentialError["code"] = "transport_failed"): Promise<T> {
    let response: Response;
    try {
      response = await fetchImpl(joinUrl(origin, path), {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        headers: { "content-type": "application/json", ...authHeaders },
        body: JSON.stringify(payload),
        signal
      });
    } catch (cause) {
      if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError(failCode, "Could not reach the AnonRouter API.");
    }
    if (!response.ok) {
      let reason = "";
      try {
        const errBody = await response.json() as { error?: { type?: string; message?: string } };
        reason = errBody?.error?.type ?? errBody?.error?.message ?? "";
      } catch { /* non-JSON error body */ }
      throw new ConfidentialError(failCode, `Request to ${path} failed with status ${response.status}${reason ? ` (${reason})` : ""}.`);
    }
    return (await response.json()) as T;
  }

  /** Whole-body opaque E2EE (a non-streaming transport, e.g. Chutes) cannot be
   *  metered token-by-token, so the gateway requires the paid ticket to RESERVE the
   *  model's full output ceiling. Resolve that ceiling from the public catalog for
   *  the exact (model, provider) route. The caller's maxOutputTokens still caps the
   *  ACTUAL generation (it travels in the encrypted request body, not the ticket). */
  async function resolveOutputCeiling(model: string, provider: string, signal?: AbortSignal): Promise<number> {
    let response: Response;
    try {
      response = await fetchImpl(joinUrl(origin, "/v1/models"), {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        headers: { accept: "application/json", ...authHeaders },
        signal
      });
    } catch {
      if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError("unsupported_request", "Could not load the model catalog to reserve the output ceiling.");
    }
    if (!response.ok) {
      throw new ConfidentialError("unsupported_request", `Could not load the model catalog (status ${response.status}).`);
    }
    const body = (await response.json()) as {
      data?: Array<{ id?: string; max_output_tokens?: number; provider_routes?: Array<{ provider?: string; max_output_tokens?: number }> }>;
    };
    const entry = Array.isArray(body.data) ? body.data.find((m) => m.id === model) : undefined;
    if (!entry) {
      throw new ConfidentialError("unsupported_request", `Model ${model} is not in the catalog; cannot reserve its output ceiling.`);
    }
    const route = Array.isArray(entry.provider_routes) ? entry.provider_routes.find((r) => r.provider === provider) : undefined;
    const ceiling = route?.max_output_tokens ?? entry.max_output_tokens;
    if (!Number.isInteger(ceiling) || (ceiling as number) <= 0) {
      throw new ConfidentialError("unsupported_request", `The catalog did not advertise an output ceiling for ${provider}/${model}.`);
    }
    return ceiling as number;
  }

  async function chat(input: ChatInput): Promise<ChatResult> {
    const transport = transportFor(input.provider);
    // Fail fast on an unsupported request BEFORE spending an attestation ticket.
    validateE2eeMessages(input.messages);
    if (!Number.isInteger(input.maxOutputTokens) || input.maxOutputTokens <= 0) {
      throw new ConfidentialError("unsupported_request", "Encrypted requests need a bounded output-token limit.");
    }

    // 0. Optional HOP 1 gate. Deliberately BEFORE the first authenticated call:
    //    a caller who requires AnonRouter's own plane to be attested must not
    //    have spent a ticket, or named a model, against a plane that is not.
    const gatewayRequirement = gatewayOptionToInput(input.requireGateway);
    if (gatewayRequirement) {
      const hop = await gatewayHop(gatewayRequirement, input.signal);
      if (hop.status !== "ok") {
        throw new ConfidentialError(
          "attestation_untrusted",
          `AnonRouter's own confidential plane did not verify (${hop.status}${hop.reason ? `: ${hop.reason}` : ""}). Nothing was sent.`
        );
      }
    }

    // 1. Authenticated, content-free attestation ticket.
    const ticketBody = await postJson<{ ticket?: unknown }>(
      "/v1/inference/attestation-tickets",
      { model: input.model, provider: input.provider },
      input.signal,
      "attestation_ticket_failed"
    );
    if (typeof ticketBody.ticket !== "string" || ticketBody.ticket.length === 0) {
      throw new ConfidentialError("attestation_ticket_failed", "The gateway returned an invalid attestation ticket.");
    }
    throwIfAborted(input.signal);

    // 2. Fresh per-generation nonce (32 bytes / 64 hex).
    const nonce = freshNonce();

    // 3. Credential-free attestation (single-use ticket in header, no Bearer).
    let attestationResponse: Response;
    try {
      attestationResponse = await fetchImpl(joinUrl(origin, "/v1/tee/attestation"), {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        headers: { "content-type": "application/json", "x-anonrouter-ticket": ticketBody.ticket },
        body: JSON.stringify({ nonce }),
        signal: input.signal
      });
    } catch (cause) {
      if (input.signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError("attestation_failed", "Could not reach the attestation relay.");
    }
    if (!attestationResponse.ok) {
      throw new ConfidentialError("attestation_failed", `Attestation failed with status ${attestationResponse.status}.`);
    }
    let attestation: AttestationResponse;
    try {
      attestation = (await attestationResponse.json()) as AttestationResponse;
    } catch {
      throw new ConfidentialError("evidence_invalid", "The attestation response could not be parsed.");
    }
    if (!attestation || typeof attestation !== "object" || !("evidence" in attestation)) {
      throw new ConfidentialError("evidence_invalid", "The attestation response did not contain evidence.");
    }
    throwIfAborted(input.signal);

    // 4. Bind the route: the gateway echoes what the ticket was bound to.
    if (typeof attestation.provider === "string" && attestation.provider !== input.provider) {
      throw new ConfidentialError("attestation_untrusted", "The attestation was bound to a different provider.");
    }
    const upstreamModel = typeof attestation.upstream_model === "string" && attestation.upstream_model.length > 0
      ? attestation.upstream_model
      : input.model;

    // 5. Gate on the gateway's normalized verdict (bound to our fresh nonce)...
    const gatewayVerdict = coerceGatewayVerdict(attestation.attestation);
    gateGatewayVerdict(gatewayVerdict, nonce);

    // 6. ...and independently gate on the raw evidence inside the transport, which
    //    also derives fresh client key material bound to the attested enclave key.
    const request = validateE2eeRequest({
      model: input.model,
      upstreamModel,
      messages: input.messages,
      maxOutputTokens: input.maxOutputTokens
    });
    const session = transport.createSession({
      upstreamModel,
      nonce,
      normalized: gatewayVerdict,
      rawEvidence: attestation.evidence
    });

    try {
      throwIfAborted(input.signal);
      // 7. Only now, with attestation trusted, mint the PAID inference ticket.
      //    A whole-body opaque relay (non-streaming, e.g. Chutes) must reserve the
      //    model's full output ceiling; a streaming relay reserves the requested cap.
      const reservedMaxOutputTokens = transport.streaming
        ? input.maxOutputTokens
        : await resolveOutputCeiling(input.model, input.provider, input.signal);
      const inferenceTicket = await postJson<{ ticket?: unknown }>(
        "/v1/inference/tickets",
        { model: input.model, provider: input.provider, e2ee: true, max_completion_tokens: reservedMaxOutputTokens },
        input.signal,
        "inference_ticket_failed"
      );
      if (typeof inferenceTicket.ticket !== "string" || inferenceTicket.ticket.length === 0) {
        throw new ConfidentialError("inference_ticket_failed", "The gateway returned an invalid inference ticket.");
      }
      throwIfAborted(input.signal);

      // 8. Encrypted inference over the credential-isolated relay.
      const completion = await transport.complete(session, request, {
        http,
        ticket: inferenceTicket.ticket,
        signal: input.signal,
        onDelta: input.onDelta
      });
      return {
        content: completion.content,
        reasoning: completion.reasoningContent,
        usage: completion.usage
      };
    } finally {
      transport.dispose(session);
    }
  }

  return { verifyRoute, verifyGateway, verifyAttestation, verify, chat };
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
}
