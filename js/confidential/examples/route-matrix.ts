/**
 * The live two-hop matrix: every confidential route AnonRouter currently serves,
 * verified from a customer's process with nothing but this SDK.
 *
 * WHAT IT ANSWERS. For each route whose privacy class is `tee` or `e2ee`:
 *
 *   hop 1  is the AnonRouter data plane I connected to the exact reviewed build,
 *          in an Intel TDX confidential VM, bound to my nonce and my origin?
 *          Chained to Intel's roots by the reviewed offline DCAP engine, so the
 *          answer is `hardware_verified` rather than "internally consistent".
 *   hop 2  did the model provider terminate my request inside an enclave whose
 *          measurements I pinned?
 *   bind   are those two hops talking about the route I actually asked for?
 *
 * THE ROUTE LIST IS READ FROM THE LIVE CATALOG, never hard-coded. A provider
 * list written down here is a list that is wrong the next time a row moves, and
 * the failure mode is silent: routes that stopped being confidential keep being
 * reported, and confidential routes that appeared are never checked at all.
 *
 * CONTENT-FREE BY CONSTRUCTION. Attestation is not a billable call and carries
 * no prompt. `--paid` additionally makes ONE minimal real request per provider
 * so the matrix says the route runs rather than only that it verifies; without
 * it nothing is charged. Nothing written to the evidence file is content: HTTP
 * status, verdict fields, check NAMES, measurement identity prefixes, timings.
 *
 * THE KEY IS READ FROM A FILE AND NOWHERE ELSE. It is never printed, hashed, put
 * in an argv or a URL, or written to the evidence. Two forms:
 *
 *   --key-file <path>   the whole file is the key
 *   --env-file <path>   read one variable out of an existing .env, so a key that
 *   [--env-var NAME]    already lives somewhere is not COPIED to run this
 *
 * Prefer --env-file. Copying a credential to a second file to satisfy a tool is
 * how a credential ends up somewhere nobody is tracking.
 *
 * Usage:
 *   npm run example:route-matrix -- --env-file ~/.../.env
 *   npm run example:route-matrix -- --env-file ~/.../.env --paid
 *   npm run example:route-matrix -- --key-file <path> --out matrix.json
 *   ... --control https://control.anonrouter.ai --inference https://api.anonrouter.ai
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { createHash } from "node:crypto";
import { createClient as createConfidentialClient } from "../src/client.js";
import { verifierFor } from "../src/verify/index.js";
import { isE2eeProvider } from "../src/transport/index.js";
import { ConfidentialError } from "../src/errors.js";
import type { RouteVerdict } from "../src/verify/route.js";
import { assembleRouteVerdict, gatewayHopVerdict, providerHopVerdict, hopUnavailable } from "../src/verify/route.js";
import { createAnonRouterDcapVerifier, describeDcapInstallation } from "../src/gateway/dcap/index.js";
import { createClient as createPlainClient } from "@anonrouter/client";

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const value = (name: string, fallback?: string) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : fallback;
};

/**
 * The reviewed offline DCAP engine, or nothing.
 *
 * Without it hop 1 caps at `cryptographically_checked`: the quote's bindings all
 * recompute, but nothing chains its signature to Intel's roots, so it is internal
 * consistency plus local pins rather than proof of silicon. The shipped
 * production policy REQUIRES hardware verification, so a run without the engine
 * fails closed on `quote_signature_chain` — correct, and worth distinguishing in
 * the report from a plane that genuinely did not verify. `--no-dcap` makes that
 * distinction observable on purpose.
 *
 * Build it with `scripts/dcap-verify-build.sh` in the AnonRouter repo and put it
 * on PATH, or name it in ANONROUTER_DCAP_VERIFIER_BIN.
 */
const CONTROL = value("control", "https://control.anonrouter.ai")!;
const INFERENCE = value("inference", "https://api.anonrouter.ai")!;
const PAID = flag("paid");
/**
 * How many times a route is sampled before it is called failing.
 *
 * Provider enclaves return an intermittent 503 that clears on retry, so a single
 * refusal is upstream flakiness, not a verdict. Calling a route broken on one
 * sample produces a matrix that disagrees with itself run to run, and the
 * disagreement gets read as instability in the checking rather than in the
 * thing being checked. A route passes if ANY sample establishes both hops, and
 * the sample count is reported so nobody has to guess how hard it was tried.
 */
const SAMPLES = Number(value("samples", "3"));

/**
 * Attestation-ticket mints per minute this harness will attempt.
 *
 * The control plane rate-limits issuance per account (a 30-per-minute bucket).
 * At twenty routes and three samples a run wants sixty mints, so an unpaced run
 * spends its second half being refused — and a refusal caused by the harness's
 * own pace is indistinguishable, from the outside, from the mint refusing the
 * route on policy. That misreading is the whole reason this pacer exists rather
 * than a retry loop: the cheapest way to avoid mistaking your own load for the
 * subject's behaviour is not to generate it.
 */
const MINTS_PER_MINUTE = Number(value("mints-per-minute", "24"));
const mintTimestamps: number[] = [];
async function paceMint(): Promise<void> {
  for (;;) {
    const now = Date.now();
    while (mintTimestamps.length > 0 && now - mintTimestamps[0] > 60_000) mintTimestamps.shift();
    if (mintTimestamps.length < MINTS_PER_MINUTE) {
      mintTimestamps.push(now);
      return;
    }
    const waitMs = 60_000 - (now - mintTimestamps[0]) + 250;
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
}

/** Read one variable out of a .env without copying the file or echoing anything. */
function readEnvVar(path: string, name: string): string | null {
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const match = raw.trim().match(new RegExp(`^${name}\\s*=\\s*(.*)$`));
    if (match) return match[1].replace(/^["']|["']$/g, "").trim();
  }
  return null;
}

const keyFile = value("key-file");
const envFile = value("env-file");
if (!keyFile && !envFile) {
  console.error("pass --env-file <path> (preferred) or --key-file <path>; the key is never taken from argv");
  process.exit(2);
}
const API_KEY = keyFile
  ? readFileSync(keyFile, "utf8").trim()
  : readEnvVar(envFile!, value("env-var", "ANONROUTER_API_KEY")!) ?? "";
if (!API_KEY.startsWith("ar_")) {
  console.error("no ar_ key was found at that path");
  process.exit(2);
}

const confidential = createConfidentialClient({
  inferenceBaseUrl: INFERENCE,
  controlBaseUrl: CONTROL,
  apiKey: API_KEY
});
const plain = createPlainClient({
  inferenceBaseUrl: INFERENCE,
  controlBaseUrl: CONTROL,
  apiKey: API_KEY
});

/**
 * SHA-256 of the DER SubjectPublicKeyInfo of the certificate the TLS session
 * actually used.
 *
 * This is the check that ties the attested TD to THIS connection. Without it the
 * quote proves a TD exists and holds a key; with it, the TD holds the key that
 * terminated the connection carrying the request. `fetch` cannot see the peer
 * certificate, so the SPKI is observed on a separate handshake to the same
 * origin — which is why the gateway's own binding must be the authority and this
 * only ever CONFIRMS it.
 */
async function observeTlsSpkiSha256(origin: string): Promise<string | null> {
  const url = new URL(origin);
  if (url.protocol !== "https:") return null;
  return new Promise((resolve) => {
    const socket = tlsConnect(
      { host: url.hostname, port: Number(url.port || 443), servername: url.hostname, rejectUnauthorized: true },
      () => {
        const cert = socket.getPeerX509Certificate?.();
        const spki = cert?.publicKey.export({ type: "spki", format: "der" }) as Buffer | undefined;
        socket.end();
        resolve(spki ? createHash("sha256").update(spki).digest("hex") : null);
      }
    );
    socket.on("error", () => resolve(null));
    socket.setTimeout(10_000, () => { socket.destroy(); resolve(null); });
  });
}

// ---- the live inventory ------------------------------------------------------

type PrivacyClass = "tee" | "e2ee";

interface Route {
  model: string;
  provider: string;
  privacyClass: PrivacyClass;
  /** `text`, `embedding`, `image`, `audio`: the modality column, verbatim. */
  modality: string;
  /** Whether this SDK ships a verifier that can grade this provider's evidence. */
  verifiable: boolean;
  /** Whether this SDK ships a client-opaque transport for it. */
  encryptable: boolean;
}

/**
 * Every callable route in the live catalog whose class is `tee` or `e2ee`.
 *
 * Read per PROVIDER ROUTE, not per model. A model row carries a top-level
 * `privacy_class` that describes its best route, so filtering on that would both
 * miss a confidential route on a model whose headline is `private`, and claim one
 * for a provider that only serves the model plainly.
 */
async function inventory(): Promise<Route[]> {
  const catalog = await plain.models();
  const routes: Route[] = [];
  for (const model of catalog.data) {
    for (const route of model.provider_routes ?? []) {
      const privacyClass = route.privacy_class;
      if (privacyClass !== "tee" && privacyClass !== "e2ee") continue;
      if (route.callable !== true) continue;
      routes.push({
        model: model.id,
        provider: route.provider,
        privacyClass,
        modality: model.model_type ?? "text",
        verifiable: verifierFor(route.provider) !== null,
        encryptable: isE2eeProvider(route.provider)
      });
    }
  }
  return routes.sort((a, b) =>
    a.provider.localeCompare(b.provider) || a.model.localeCompare(b.model));
}

// ---- classification ----------------------------------------------------------

/**
 * Why a route did not pass, in the four categories that call for four different
 * actions. Collapsing them is how "the provider is down" gets filed as "our code
 * is broken", and how insufficient evidence gets quietly filed as availability.
 */
type Classification =
  /** Ours. Something in AnonRouter's or this SDK's code is wrong. */
  | "code_defect"
  /** NOBODY's. The harness hit a rate limit and never got an answer. */
  | "not_measured_rate_limited"
  /** Ours. The route is admitted, or refused, by policy that is wrong. */
  | "routing_admission_policy_defect"
  /** Theirs, and transient. The provider or its enclave did not answer. */
  | "provider_availability"
  /** Theirs, and not transient. The evidence does not establish the claim. */
  | "insufficient_evidence";

interface RouteResult {
  provider: string;
  model: string;
  privacy_class: PrivacyClass;
  modality: string;
  hop1_state: string;
  hop2_state: string;
  overall_state: string;
  trusted: boolean;
  binding_mismatches: unknown[];
  privacy_modality_source: string;
  content_visible_to_anonrouter: boolean;
  hop2_failed_checks: string[];
  hop2_advisory_gaps: string[];
  reason: string | null;
  classification: Classification | null;
  latency_ms: number;
  /** How many verification samples this route needed, and how many it got. */
  samples: number;
  paid_call?: Record<string, unknown>;
}

function classify(verdict: RouteVerdict, route: Route, detail: string): Classification | null {
  if (verdict.trusted) return null;
  if (verdict.bindingMismatches.length > 0) return "routing_admission_policy_defect";

  // A refusal this harness provoked is not a finding about the route. Checked
  // FIRST, because it arrives wearing the same error code as a policy refusal.
  if (/status 429/.test(detail) || /rate_limited/.test(detail)) return "not_measured_rate_limited";

  const reason = verdict.provider.reason ?? "";
  // A mint that refuses a route the catalog publishes as callable and
  // confidential is an admission decision disagreeing with a catalog decision.
  if (reason.includes("attestation_ticket_failed")) return "routing_admission_policy_defect";
  // The relay reached the enclave and the enclave did not answer.
  if (reason.includes("worker_attestation_failed") || reason.includes("attestation_failed")) {
    return "provider_availability";
  }
  if (reason === "provider_not_verifiable") return "routing_admission_policy_defect";
  // The evidence arrived and did not hold. That is the verifier working.
  if (verdict.provider.failedChecks.length > 0) return "insufficient_evidence";
  if (!verdict.gateway.requested) return "code_defect";
  return verdict.gateway.state === "untrusted" ? "insufficient_evidence" : "code_defect";
}

// ---- the paid canary ---------------------------------------------------------

/**
 * ONE minimal real request, provider-pinned, priced in fractions of a cent.
 *
 * Verification says the route can be established. It does not say the route
 * runs: a mint can succeed, an enclave can attest, and the request can still be
 * refused downstream. The two facts are worth separating, so this is opt-in and
 * reported as its own column rather than folded into the verdict.
 *
 * Provider pinning is the point. An unpinned call resolves through Auto, which
 * picks a route per request, so a green result would say nothing about the route
 * that was just verified. Anything the response says about the provider is
 * checked against the pin.
 */
/**
 * Name a paid refusal by its CAUSE, from AnonRouter's own error vocabulary.
 *
 * `transport_failed` is the SDK's catch-all for a control call that did not
 * return 2xx, so on its own it hides three unrelated situations that call for
 * three different responses. The distinctions that matter here:
 *
 *   admission_ceiling_exceeded  A whole-body E2EE route reserves the model's
 *                               ENTIRE context window, because the relay cannot
 *                               read a token count out of ciphertext. When that
 *                               window is larger than the deployment's
 *                               per-request admission limit, the route can never
 *                               be admitted — by any caller, with any request.
 *                               That is a published-but-uncallable route, not a
 *                               transient failure and not a caller error.
 *   insufficient_balance        The same worst-case reservation exceeded the
 *                               TEST ACCOUNT's funds. A property of the
 *                               credential, not of the route.
 */
function refusalKind(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/exceeding the permanent \d+-token admission limit/.test(message)) return "admission_ceiling_exceeded";
  if (/Insufficient balance/i.test(message)) return "insufficient_balance";
  if (error instanceof ConfidentialError) return error.code;
  const status = (error as { status?: number }).status;
  return status ? `http_${status}` : "unknown";
}

async function paidCall(route: Route): Promise<Record<string, unknown>> {
  const started = Date.now();
  try {
    if (route.modality === "embedding") {
      const result = await plain.embeddings({
        model: route.model,
        provider: route.provider,
        input: "ok"
      });
      return {
        kind: "embeddings",
        ok: true,
        latency_ms: Date.now() - started,
        vectors: result.data.length,
        dimensions: Array.isArray(result.data[0]?.embedding) ? (result.data[0].embedding as number[]).length : null,
        // The relay rewrites the model back to the PUBLIC id, so this is the
        // route echo, not the provider's internal name.
        echoed_model: result.model,
        model_matches_request: result.model === route.model,
        prompt_tokens: result.usage?.prompt_tokens ?? null
      };
    }
    if (route.privacyClass === "e2ee" && route.encryptable) {
      const result = await confidential.chat({
        model: route.model,
        provider: route.provider,
        messages: [{ role: "user", content: "Reply with the single word: ok" }],
        maxOutputTokens: 16
      });
      return {
        kind: "e2ee-chat",
        ok: true,
        latency_ms: Date.now() - started,
        // Length only. The plaintext exists solely in this process and is never
        // recorded, which is the property the route exists to provide.
        decrypted_chars: result.content.length,
        completion_tokens: result.usage?.completionTokens ?? null
      };
    }
    const completion = await plain.chat({
      model: route.model,
      provider: route.provider,
      messages: [{ role: "user", content: "Reply with the single word: ok" }],
      maxTokens: 16
    });
    return {
      kind: "tee-chat",
      ok: true,
      latency_ms: Date.now() - started,
      reply_chars: (completion.choices[0]?.message?.content ?? "").length,
      echoed_model: completion.model,
      model_matches_request: completion.model === route.model,
      completion_tokens: completion.usage?.completion_tokens ?? null
    };
  } catch (error) {
    const status = (error as { status?: number }).status ?? null;
    const code = error instanceof ConfidentialError ? error.code : null;
    return {
      kind: route.modality === "embedding" ? "embeddings" : route.privacyClass === "e2ee" ? "e2ee-chat" : "tee-chat",
      ok: false,
      latency_ms: Date.now() - started,
      status,
      code,
      refusal: refusalKind(error),
      // The message itself is bounded upstream text and is not recorded; only
      // the KIND above, which is matched against our own error vocabulary.
      message_present: error instanceof Error && error.message.length > 0
    };
  }
}

// ---- run ---------------------------------------------------------------------

async function main() {
  const routes = await inventory();
  const byProvider = new Map<string, number>();
  for (const route of routes) byProvider.set(route.provider, (byProvider.get(route.provider) ?? 0) + 1);

  console.log(`live confidential routes: ${routes.length}`);
  for (const [provider, count] of [...byProvider].sort()) {
    const verifiable = verifierFor(provider) !== null;
    console.log(`  ${provider.padEnd(10)} ${String(count).padStart(2)} route(s)  verifier=${verifiable ? "yes" : "NO"}`);
  }

  const observedSpki = await observeTlsSpkiSha256(INFERENCE);
  console.log(`observed TLS SPKI (${INFERENCE}): ${observedSpki ? `${observedSpki.slice(0, 16)}…` : "not observable"}`);

  const dcapReport = describeDcapInstallation();
  const useDcap = !flag("no-dcap") && dcapReport.available;
  console.log(
    `\ndcap engine: ${useDcap
      ? `${dcapReport.origin} sha256=${(dcapReport.binarySha256 ?? "").slice(0, 16)}… target=${dcapReport.target}`
      : flag("no-dcap")
        ? "disabled by --no-dcap"
        : `NOT INSTALLED (${dcapReport.reason}) — hop 1 cannot reach hardware_verified`}`
  );
  const gatewayInput = {
    ...(useDcap ? { chainVerifier: createAnonRouterDcapVerifier() } : {}),
    ...(observedSpki ? { observedTlsSpkiSha256: observedSpki } : {})
  };
  // Hop 1 is a property of the ORIGIN, not of the route, so it is established
  // exactly once and carried onto every route below.
  // A throw is a legitimate answer: an origin this package ships no pin for
  // cannot be verified at all, and reporting what the server says about itself
  // instead would be reading the claim back to the caller.
  const gatewayStarted = Date.now();
  let gateway: Awaited<ReturnType<typeof confidential.verifyGateway>> | null = null;
  let gatewayError: string | null = null;
  try {
    gateway = await confidential.verifyGateway(gatewayInput);
  } catch (error) {
    gatewayError = error instanceof ConfidentialError ? error.code : "gateway_verification_failed";
  }
  console.log(
    `\nhop 1 (${INFERENCE}): ${gateway
      ? `status=${gateway.verdict.status} level=${gateway.verdict.verificationLevel} policy=${gateway.policy.origin}`
      : `unavailable (${gatewayError})`} ${Date.now() - gatewayStarted}ms`
  );

  // HOP 1 IS ESTABLISHED ONCE, and the same verdict is carried onto every route.
  //
  // It is a property of the ORIGIN, not of the route: the same TD answers all of
  // them, and one nonce-bound quote says everything a second one would. Asking
  // per route also trips the endpoint's flood guard (429) at this many routes,
  // which turns a redundant question into a worse answer.
  const gatewayHop = gateway
    ? gatewayHopVerdict(gateway.verdict)
    : hopUnavailable(gatewayError ?? "gateway hop not established");

  const results: RouteResult[] = [];
  for (const route of routes) {
    const started = Date.now();
    // Sample until a route establishes both hops, or until the budget is spent.
    // A route is only called failing when EVERY sample agreed, so a single
    // upstream 503 cannot demote a working route.
    let detail = "";
    const attest = async () => {
      await paceMint();
      try {
        const result = await confidential.verifyAttestation({
          model: route.model,
          provider: route.provider,
          // PINNED from the catalog row, so a route served under a different
          // class is a mismatch rather than something adopted silently.
          privacyClass: route.privacyClass
        });
        return assembleRouteVerdict({
          route: {
            provider: route.provider,
            model: route.model,
            privacyModality: result.privacyModality,
            privacyModalitySource: result.privacyModalitySource
          },
          gateway: gatewayHop,
          provider: providerHopVerdict(result.verdict),
          // The gateway's OWN echo, so the cross-binding compares two
          // independent statements rather than one restated.
          gatewayEcho: {
            provider: result.gatewayRoute.provider,
            model: result.gatewayRoute.model,
            privacyClass: result.gatewayRoute.privacyClass
          },
          attestedUpstreamModel: result.gatewayRoute.upstreamModel
        });
      } catch (error) {
        const code = error instanceof ConfidentialError ? error.code : "provider_verification_failed";
        // Kept out of the evidence file: it is upstream text. Used only to tell
        // one refusal apart from another, against our own error vocabulary.
        detail = error instanceof Error ? error.message : "";
        return assembleRouteVerdict({
          route: {
            provider: route.provider,
            model: route.model,
            privacyModality: route.privacyClass,
            privacyModalitySource: "caller-pinned"
          },
          gateway: gatewayHop,
          provider: {
            requested: true,
            state: "untrusted",
            meaning: "A required check failed. Do not proceed on this route.",
            reason: code,
            failedChecks: [code],
            advisoryGaps: []
          }
        });
      }
    };
    let verdict = await attest();
    let samples = 1;
    while (!verdict.trusted && samples < SAMPLES) {
      samples += 1;
      verdict = await attest();
    }
    const result: RouteResult = {
      provider: route.provider,
      model: route.model,
      privacy_class: route.privacyClass,
      modality: route.modality,
      hop1_state: verdict.gateway.state,
      hop2_state: verdict.provider.state,
      overall_state: verdict.overallState,
      trusted: verdict.trusted,
      binding_mismatches: verdict.bindingMismatches,
      privacy_modality_source: verdict.route.privacyModalitySource ?? "unestablished",
      content_visible_to_anonrouter: verdict.contentVisibleToAnonRouter,
      hop2_failed_checks: verdict.provider.failedChecks,
      hop2_advisory_gaps: verdict.provider.advisoryGaps,
      reason: verdict.reason,
      classification: classify(verdict, route, detail),
      latency_ms: Date.now() - started,
      samples
    };
    if (PAID) result.paid_call = await paidCall(route);
    results.push(result);

    const mark = result.trusted ? "PASS" : "FAIL";
    console.log(
      `${mark}  ${route.provider.padEnd(8)} ${route.privacyClass.padEnd(5)} ${route.modality.padEnd(10)} `
      + `${route.model.padEnd(38)} hop1=${result.hop1_state} hop2=${result.hop2_state}`
      + (result.classification ? `  [${result.classification}]` : "")
      + (samples > 1 ? `  samples=${samples}` : "")
      + (result.paid_call ? `  paid=${result.paid_call.ok ? "ok" : `refused(${result.paid_call.refusal ?? result.paid_call.code})`}` : "")
    );
  }

  const passed = results.filter((r) => r.trusted).length;
  console.log(`\nboth hops established: ${passed}/${results.length}`);
  const buckets = new Map<string, number>();
  for (const r of results) if (r.classification) buckets.set(r.classification, (buckets.get(r.classification) ?? 0) + 1);
  for (const [name, count] of [...buckets].sort()) console.log(`  ${name}: ${count}`);

  const out = value("out");
  if (out) {
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify({
      control_origin: CONTROL,
      inference_origin: INFERENCE,
      paid: PAID,
      dcap_engine: useDcap
        ? { origin: dcapReport.origin, sha256: dcapReport.binarySha256, target: dcapReport.target }
        : { origin: null, reason: flag("no-dcap") ? "disabled" : dcapReport.reason },
      observed_tls_spki_sha256: observedSpki,
      samples_per_route: SAMPLES,
      gateway: gateway
        ? {
          status: gateway.verdict.status,
          verification_level: gateway.verdict.verificationLevel,
          reason: gateway.verdict.reason,
          policy_origin: gateway.policy.origin,
          policy_source: gateway.policy.source,
          policy_version: gateway.policy.version,
          tcb_status: gateway.verdict.tcbStatus ?? null,
          failed_checks: gateway.verdict.checks.filter((c) => c.required && !c.passed).map((c) => c.name),
          advisory_gaps: gateway.verdict.checks.filter((c) => !c.required && !c.passed).map((c) => c.name)
        }
        : { status: "unavailable", reason: gatewayError },
      routes: results
    }, null, 1)}\n`);
    console.log(`\nwrote content-free evidence for ${results.length} routes to ${out}`);
  }
}

await main();
