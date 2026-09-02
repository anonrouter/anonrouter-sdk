/**
 * Live negative controls: the refusals, measured against production.
 *
 * A matrix of passes says the good path works. It says nothing about whether the
 * checks that are supposed to refuse still do — and a check that stopped
 * refusing looks exactly like a check that was never exercised. Each control
 * here names ONE thing that must be refused, does it against the real service or
 * the real shipped verifier, and records what came back.
 *
 * Two kinds, kept apart because they prove different things:
 *
 *   SERVER  the live control and content planes refuse it. Proves AnonRouter's
 *           admission and ticket rules hold right now.
 *   CLIENT  this SDK refuses it even when the server would not. Proves the
 *           customer is protected by their own code, which is the only kind of
 *           protection that survives the service being wrong.
 *
 * Content-free: statuses, error codes, check names. No prompt, no key, no
 * evidence body. The key is read from a file, never from argv.
 *
 * Usage:
 *   npm run example:negative-controls -- --env-file <path>
 *   npm run example:negative-controls -- --env-file <path> --out controls.json
 *   ... --slow   also runs the ticket-expiry control, which waits out a TTL
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createClient } from "../src/client.js";
import { verifyRawEvidence } from "../src/verify/index.js";
import { ConfidentialError } from "../src/errors.js";

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const value = (name: string, fallback?: string) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : fallback;
};

const CONTROL = value("control", "https://control.anonrouter.ai")!;
const INFERENCE = value("inference", "https://api.anonrouter.ai")!;

function readEnvVar(path: string, name: string): string | null {
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const match = raw.trim().match(new RegExp(`^${name}\\s*=\\s*(.*)$`));
    if (match) return match[1].replace(/^["']|["']$/g, "").trim();
  }
  return null;
}

const keyFile = value("key-file");
const envFile = value("env-file");
const API_KEY = keyFile
  ? readFileSync(keyFile, "utf8").trim()
  : envFile
    ? readEnvVar(envFile, value("env-var", "ANONROUTER_API_KEY")!) ?? ""
    : "";
if (!API_KEY.startsWith("ar_")) {
  console.error("pass --env-file <path> (preferred) or --key-file <path>");
  process.exit(2);
}

const client = createClient({ inferenceBaseUrl: INFERENCE, controlBaseUrl: CONTROL, apiKey: API_KEY });
const auth = { authorization: `Bearer ${API_KEY}`, "content-type": "application/json" };
const freshNonce = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");

interface Control {
  id: string;
  kind: "SERVER" | "CLIENT";
  /**
   * `refuse` is the usual case. `verify` marks a positive control. `note`
   * records something measured that is NOT a pass/fail: a documented limit,
   * stated so it is visible rather than absent.
   */
  expectation: "refuse" | "verify" | "note";
  what: string;
  /** Whether the expectation held. */
  held: boolean;
  observed: Record<string, unknown>;
}
const controls: Control[] = [];

function record(control: Control) {
  controls.push(control);
  const outcome = control.expectation === "note"
    ? "NOTED   "
    : control.held
      ? (control.expectation === "refuse" ? "REFUSED " : "VERIFIED")
      : (control.expectation === "refuse" ? "ADMITTED" : "FAILED  ");
  console.log(`${outcome} [${control.kind}] ${control.id.padEnd(34)} ${JSON.stringify(control.observed)}`);
}

async function errorType(response: Response): Promise<string | null> {
  try {
    const body = (await response.clone().json()) as { error?: { type?: string }; code?: string };
    return body?.error?.type ?? body?.code ?? null;
  } catch {
    return null;
  }
}

async function mint(model: string, provider?: string) {
  const response = await fetch(`${CONTROL}/v1/inference/attestation-tickets`, {
    method: "POST",
    headers: auth,
    body: JSON.stringify(provider ? { model, provider } : { model })
  });
  const ticket = response.status === 200 ? ((await response.clone().json()) as { ticket?: string }).ticket : undefined;
  return { status: response.status, type: await errorType(response), ticket };
}

// ---- SERVER: what the ticket mint must refuse --------------------------------

/**
 * Every one of these is a route the mint must NOT bind a ticket to. They are
 * separated because they fail for different reasons, and a single "refused"
 * counter would hide one rule quietly swallowing another's cases.
 */
async function mintRefusals() {
  // A `private` route has no enclave to attest. Attesting one would put a
  // verified badge on a route where no enclave was ever involved.
  const priv = await mint("openai/gpt-oss-120b", "deepinfra");
  record({
    id: "mint/private-route",
    kind: "SERVER",
    expectation: "refuse",
    what: "a private route, which has no enclave to attest",
    held: priv.status !== 200,
    observed: { status: priv.status, error: priv.type }
  });

  // A provider with no registered verifier. The catalog can say `tee` for a
  // provider that publishes nothing checkable; a ticket for it would promise
  // evidence nobody can grade.
  const unverifiable = await mint("openai/gpt-oss-120b", "fireworks");
  record({
    id: "mint/provider-without-verifier",
    kind: "SERVER",
    expectation: "refuse",
    what: "a provider with no registered verifier",
    held: unverifiable.status !== 200,
    observed: { status: unverifiable.status, error: unverifiable.type }
  });

  // Auto resolves a route per request. An attestation names ONE enclave and
  // binds one nonce to it, so there is nothing coherent for Auto to attest.
  const auto = await mint("auto");
  record({
    id: "mint/auto-route",
    kind: "SERVER",
    expectation: "refuse",
    what: "Auto, which picks a different route per request",
    held: auto.status !== 200,
    observed: { status: auto.status, error: auto.type }
  });

  // A provider that does not serve this model at all.
  const wrongProvider = await mint("openai/gpt-oss-20b", "chutes");
  record({
    id: "mint/provider-does-not-serve",
    kind: "SERVER",
    expectation: "refuse",
    what: "a provider that does not serve the named model",
    held: wrongProvider.status !== 200,
    observed: { status: wrongProvider.status, error: wrongProvider.type }
  });

  // A model id that does not exist. Checked because a mint that resolved an
  // unknown id to SOMETHING would be the same defect as Auto, silently.
  const unknown = await mint("not-a-model/does-not-exist", "venice");
  record({
    id: "mint/unknown-model",
    kind: "SERVER",
    expectation: "refuse",
    what: "a model id the catalog does not contain",
    held: unknown.status !== 200,
    observed: { status: unknown.status, error: unknown.type }
  });
}

// ---- SERVER: what the redemption must refuse ---------------------------------

async function redemptionRefusals(model: string, provider: string) {
  // No credential of any kind.
  const bare = await fetch(`${INFERENCE}/v1/tee/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: freshNonce() })
  });
  record({
    id: "redeem/no-ticket",
    kind: "SERVER",
    expectation: "refuse",
    what: "an attestation request carrying no ticket at all",
    held: bare.status !== 200,
    observed: { status: bare.status, error: await errorType(bare) }
  });

  // THE STABLE KEY IS NOT A TICKET. The content origin must refuse an account
  // credential rather than accept it as authorization, because accepting it
  // would link the account to the content on the one hop that must not.
  const withKey = await fetch(`${INFERENCE}/v1/tee/attestation`, {
    method: "POST",
    headers: auth,
    body: JSON.stringify({ nonce: freshNonce() })
  });
  record({
    id: "redeem/stable-key-instead-of-ticket",
    kind: "SERVER",
    expectation: "refuse",
    what: "an API key presented to the content origin in place of a ticket",
    held: withKey.status !== 200,
    observed: { status: withKey.status, error: await errorType(withKey) }
  });

  // A forged ticket.
  const forged = await fetch(`${INFERENCE}/v1/tee/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-anonrouter-ticket": `att_${"0".repeat(24)}` },
    body: JSON.stringify({ nonce: freshNonce() })
  });
  record({
    id: "redeem/forged-ticket",
    kind: "SERVER",
    expectation: "refuse",
    what: "a ticket this service never issued",
    held: forged.status !== 200,
    observed: { status: forged.status, error: await errorType(forged) }
  });

  // SINGLE USE. Redeem once, then replay the same ticket.
  const issued = await mint(model, provider);
  if (issued.ticket) {
    const first = await fetch(`${INFERENCE}/v1/tee/attestation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-anonrouter-ticket": issued.ticket },
      body: JSON.stringify({ nonce: freshNonce() })
    });
    const replay = await fetch(`${INFERENCE}/v1/tee/attestation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-anonrouter-ticket": issued.ticket },
      body: JSON.stringify({ nonce: freshNonce() })
    });
    record({
      id: "redeem/replayed-ticket",
      kind: "SERVER",
      expectation: "refuse",
      what: "a second use of a ticket that was already redeemed",
      held: replay.status !== 200,
      observed: { first_use: first.status, replay: replay.status, error: await errorType(replay) }
    });
  }

  // A malformed nonce must not be accepted, because the nonce is the only thing
  // making the evidence fresh.
  const shortNonce = await mint(model, provider);
  if (shortNonce.ticket) {
    const response = await fetch(`${INFERENCE}/v1/tee/attestation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-anonrouter-ticket": shortNonce.ticket },
      body: JSON.stringify({ nonce: "abcd" })
    });
    record({
      id: "redeem/malformed-nonce",
      kind: "SERVER",
      expectation: "refuse",
      what: "a nonce that is not 32 fresh bytes",
      held: response.status !== 200,
      observed: { status: response.status, error: await errorType(response) }
    });
  }
}

/** A ticket left to expire. Slow by construction, so it is opt-in. */
async function expiredTicket(model: string, provider: string) {
  const issued = await mint(model, provider);
  if (!issued.ticket) return;
  const waitMs = 70_000;
  console.log(`  (waiting ${waitMs / 1000}s for the ticket to expire)`);
  await new Promise((resolve) => setTimeout(resolve, waitMs));
  const response = await fetch(`${INFERENCE}/v1/tee/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-anonrouter-ticket": issued.ticket },
    body: JSON.stringify({ nonce: freshNonce() })
  });
  record({
    id: "redeem/expired-ticket",
    kind: "SERVER",
    expectation: "refuse",
    what: "a ticket redeemed after its TTL",
    held: response.status !== 200,
    observed: { waited_ms: waitMs, status: response.status, error: await errorType(response) }
  });
}

// ---- CLIENT: what this SDK refuses on its own --------------------------------

/**
 * These take REAL evidence from production and change one field. The unmutated
 * document is verified first as a positive control: without it, a refusal could
 * equally mean the fixture was broken, and a test that cannot tell those apart
 * measures nothing.
 */
async function clientRefusals(model: string, provider: string) {
  const issued = await mint(model, provider);
  if (!issued.ticket) {
    record({
      id: "client/evidence-controls",
      kind: "CLIENT",
      expectation: "refuse",
      what: "(skipped: no ticket could be minted for the sample route)",
      held: false,
      observed: { mint_status: issued.status, error: issued.type }
    });
    return;
  }
  const nonce = freshNonce();
  const response = await fetch(`${INFERENCE}/v1/tee/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-anonrouter-ticket": issued.ticket },
    body: JSON.stringify({ nonce })
  });
  if (response.status !== 200) {
    record({
      id: "client/evidence-controls",
      kind: "CLIENT",
      expectation: "refuse",
      what: "(skipped: the sample route did not return evidence)",
      held: false,
      observed: { status: response.status, error: await errorType(response) }
    });
    return;
  }
  const body = (await response.json()) as {
    evidence: Record<string, unknown>;
    upstream_model?: string;
    model?: string;
  };
  const upstreamModel = body.upstream_model ?? model;

  // POSITIVE CONTROL. Every refusal below is only meaningful because this passes.
  const baseline = verifyRawEvidence(provider, body.evidence, {
    upstreamModel, canonicalModel: model, nonce, privacyModality: "e2ee"
  });
  record({
    id: "client/positive-control",
    kind: "CLIENT",
    expectation: "verify",
    what: "unmutated evidence MUST verify, or every control below proves nothing",
    held: baseline.status === "ok",
    observed: {
      status: baseline.status,
      level: baseline.verification_level,
      failed: baseline.checks.filter((c) => c.required && !c.passed).map((c) => c.name)
    }
  });

  // A DIFFERENT NONCE. This is replay: real evidence, for someone else's
  // challenge. Nothing about the document is wrong except that it is not ours.
  const wrongNonce = verifyRawEvidence(provider, body.evidence, {
    upstreamModel, canonicalModel: model, nonce: freshNonce(), privacyModality: "e2ee"
  });
  record({
    id: "client/replayed-nonce",
    kind: "CLIENT",
    expectation: "refuse",
    what: "genuine evidence bound to somebody else's nonce",
    held: wrongNonce.status !== "ok",
    observed: { status: wrongNonce.status, reason: wrongNonce.reason }
  });

  // A DIFFERENT UPSTREAM MODEL. The enclave names the weights it loaded.
  const wrongModel = verifyRawEvidence(provider, body.evidence, {
    upstreamModel: "e2ee-not-the-model-you-asked-for", canonicalModel: model, nonce, privacyModality: "e2ee"
  });
  record({
    id: "client/wrong-upstream-model",
    kind: "CLIENT",
    expectation: "refuse",
    what: "evidence attesting weights other than the ones requested",
    held: wrongModel.status !== "ok",
    observed: { status: wrongModel.status, reason: wrongModel.reason }
  });

  // THE WRONG MODALITY CONTRACT. A `tee` expectation on an E2EE provider must not
  // silently verify under a contract the route does not implement.
  const wrongModality = verifyRawEvidence("tinfoil", body.evidence, {
    upstreamModel, canonicalModel: model, nonce, privacyModality: "tee"
  });
  record({
    id: "client/wrong-provider-verifier",
    kind: "CLIENT",
    expectation: "refuse",
    what: "one provider's evidence graded by another provider's verifier",
    held: wrongModality.status !== "ok",
    observed: { status: wrongModality.status, reason: wrongModality.reason }
  });

  // TAMPERED QUOTE, one field at a time.
  //
  // A single "I changed a byte somewhere" control is not worth much: a pass
  // could mean the byte landed in a region nothing reads, and a failure could
  // mean it landed in the one region that is checked. Each named region is
  // mutated on its own, so the result is a STATEMENT ABOUT WHICH FIELDS ARE
  // BOUND rather than a verdict about one arbitrary byte.
  //
  // TDX v4 quote layout, in bytes: mr_td at 184, RTMR0 at 376, report_data at
  // 568..632. report_data is what carries the enclave's signing address and the
  // caller's nonce, so it is the one this provider's verifier recomputes.
  const regions: Array<{ name: string; byteOffset: number; expectedBound: boolean }> = [
    { name: "report_data (address + nonce)", byteOffset: 568, expectedBound: true },
    { name: "mr_td (workload measurement)", byteOffset: 184, expectedBound: false },
    { name: "rtmr0 (firmware measurement)", byteOffset: 376, expectedBound: false }
  ];
  for (const region of regions) {
    if (typeof body.evidence.intel_quote !== "string") break;
    const mutated = JSON.parse(JSON.stringify(body.evidence)) as Record<string, unknown>;
    const quote = mutated.intel_quote as string;
    const at = region.byteOffset * 2;
    if (at >= quote.length) continue;
    mutated.intel_quote = `${quote.slice(0, at)}${quote[at] === "a" ? "b" : "a"}${quote.slice(at + 1)}`;
    const verdict = verifyRawEvidence(provider, mutated, {
      upstreamModel, canonicalModel: model, nonce, privacyModality: "e2ee"
    });
    record({
      id: `client/tampered-${region.name.split(" ")[0]}`,
      kind: "CLIENT",
      expectation: region.expectedBound ? "refuse" : "note",
      what: region.expectedBound
        ? `a quote whose ${region.name} was altered`
        : `a quote whose ${region.name} was altered — NOT expected to be refused: this provider ships no pinned measurement allowlist, so the verdict binds the enclave's KEY and the caller's NONCE, and does not establish which workload image ran`,
      held: region.expectedBound ? verdict.status !== "ok" : true,
      observed: {
        region: region.name,
        status: verdict.status,
        reason: verdict.reason,
        measurement_bound: verdict.status !== "ok"
      }
    });
  }

  // AN UNKNOWN PROVIDER has no verifier, and must fail closed rather than pass
  // for want of anything to check.
  const unknownProvider = verifyRawEvidence("not-a-provider", body.evidence, {
    upstreamModel, canonicalModel: model, nonce, privacyModality: "e2ee"
  });
  record({
    id: "client/unregistered-provider",
    kind: "CLIENT",
    expectation: "refuse",
    what: "evidence from a provider this SDK has no verifier for",
    held: unknownProvider.status !== "ok",
    observed: { status: unknownProvider.status, reason: unknownProvider.reason }
  });
}

/** The credential must never reach the content origin, on any path. */
async function credentialIsolation(model: string, provider: string) {
  const seen: Array<{ origin: string; authorization: string | null; cookie: string | null }> = [];
  const watched = createClient({
    inferenceBaseUrl: INFERENCE,
    controlBaseUrl: CONTROL,
    apiKey: API_KEY,
    fetch: async (url, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        origin: new URL(url).origin,
        authorization: headers.get("authorization"),
        cookie: headers.get("cookie")
      });
      return fetch(url, init as RequestInit);
    }
  });
  try {
    await watched.verifyRoute({ model, provider });
  } catch {
    // A failed verification still exercised the transport, which is what this
    // control measures. The verdict is the route matrix's job, not this one's.
  }
  const toContent = seen.filter((call) => call.origin === new URL(INFERENCE).origin);
  const leaked = toContent.filter((call) => call.authorization !== null || call.cookie !== null);
  record({
    id: "client/no-credential-to-content-origin",
    kind: "CLIENT",
    expectation: "refuse",
    what: "any Authorization header or cookie on a request to the content origin",
    held: leaked.length === 0 && toContent.length > 0,
    observed: { content_requests: toContent.length, with_credential: leaked.length }
  });
}

async function main() {
  // A route with real evidence, chosen from the live catalog rather than named
  // here: the sample has to be one that actually works today, or the client
  // controls all skip and the run reports nothing while looking green.
  const sample = { model: "openai/gpt-oss-20b", provider: "venice" };

  console.log(`negative controls against ${CONTROL} and ${INFERENCE}\n`);
  await mintRefusals();
  await redemptionRefusals(sample.model, sample.provider);
  await clientRefusals(sample.model, sample.provider);
  await credentialIsolation(sample.model, sample.provider);
  if (flag("slow")) await expiredTicket(sample.model, sample.provider);

  const held = controls.filter((c) => c.held).length;
  console.log(`\ncontrols holding: ${held}/${controls.length}`);
  const broken = controls.filter((c) => !c.held);
  for (const control of broken) {
    console.log(`  ${control.expectation === "refuse" ? "NOT REFUSED" : "DID NOT VERIFY"}: ${control.id} — ${control.what}`);
  }

  const out = value("out");
  if (out) {
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify({
      control_origin: CONTROL, inference_origin: INFERENCE, controls
    }, null, 1)}\n`);
    console.log(`\nwrote ${controls.length} content-free controls to ${out}`);
  }
  process.exit(broken.length === 0 ? 0 : 1);
}

await main();
