// Verify first, send only if the verdict clears the bar, and re-verify at send time.
//
//   npx tsx examples/verify-then-call.ts
//
// This is the shape most applications actually want, and it is three ideas rather
// than one:
//
//   1. GATE BEFORE SENDING. Nothing leaves the process until the route reaches the
//      state this program requires. A verdict you look at after sending is a log
//      entry, not a control.
//
//   2. RE-VERIFY AT SEND TIME. `chat({ requireGateway })` establishes hop 1 again,
//      with a fresh nonce, before it spends a ticket or names a model. A verdict
//      from thirty seconds ago is a fact about thirty seconds ago; the deployment
//      can be replaced between the two calls, and the whole point of the nonce is
//      that each answer covers exactly one challenge.
//
//   3. SAY WHAT WAS NOT COVERED. A `trusted` verdict for a call that never asked
//      about hop 1 establishes the provider enclave and nothing about who routed
//      the request there. This program prints that distinction instead of hiding it.
//
// Reads ANONROUTER_API_KEY (required, inference scope) and optionally
// ANONROUTER_BASE_URL, ANONROUTER_MODEL, ANONROUTER_PROVIDER, ANONROUTER_REQUIRE,
// PROMPT, MAX_TOKENS.
//
// BILLABLE: the second half makes one small real inference call.

import "./_env.js";
import {
  createClient,
  atLeast,
  describeState,
  TRUSTED_STATES,
  type RouteVerificationState
} from "../src/index.js";
import { createAnonRouterDcapVerifier, describeDcapInstallation } from "../src/gateway/dcap/index.js";

const BASE_URL = process.env.ANONROUTER_BASE_URL ?? "https://api.anonrouter.ai";
const CONTROL_URL = process.env.ANONROUTER_CONTROL_URL ?? "https://control.anonrouter.ai";
const MODEL = process.env.ANONROUTER_MODEL ?? "openai/gpt-oss-120b";
const PROVIDER = process.env.ANONROUTER_PROVIDER ?? "near-ai";
const PROMPT = process.env.PROMPT ?? "In one sentence: what does attestation prove?";
const MAX_TOKENS = Number(process.env.MAX_TOKENS ?? 64);

const requested = (process.env.ANONROUTER_REQUIRE ?? "cryptographically_checked") as RouteVerificationState;
if (!TRUSTED_STATES.includes(requested)) {
  console.error(`ANONROUTER_REQUIRE must be one of ${TRUSTED_STATES.join(", ")}.`);
  process.exit(2);
}

const apiKey = process.env.ANONROUTER_API_KEY;
if (!apiKey) {
  console.error("Set ANONROUTER_API_KEY to your AnonRouter API key (inference scope).");
  process.exit(2);
}

const client = createClient({ baseUrl: BASE_URL, controlBaseUrl: CONTROL_URL, apiKey });

// The chain verifier is what makes `hardware_verified` reachable. Supplying it
// unconditionally is the right default: with no engine installed it fails the
// chain check rather than silently downgrading, and a policy that does not
// require hardware verification is unaffected either way.
const engine = describeDcapInstallation();
const gateway = {
  chainVerifier: createAnonRouterDcapVerifier()
};
console.log(engine.available
  ? `DCAP engine: ${engine.binaryPath}`
  : `DCAP engine: none installed, so hardware_verified is out of reach here (${engine.reason})`);

// ---- 1. Verify, and stop here if it does not clear the bar -------------------

const verdict = await client.verifyRoute({ model: MODEL, provider: PROVIDER, gateway });

console.log(`\nroute      ${verdict.route.provider}/${verdict.route.model}`);
console.log(`modality   ${verdict.route.privacyModality}`
  + (verdict.contentVisibleToAnonRouter
    ? "  (a TEE route: AnonRouter sees your plaintext to route and meter it)"
    : "  (E2EE: only ciphertext reaches AnonRouter's relay)"));
for (const [label, hop] of [["hop 1 gateway ", verdict.gateway], ["hop 2 provider", verdict.provider]] as const) {
  console.log(`${label}  ${hop.requested ? hop.state : "not requested"}`);
  if (hop.requested) {
    console.log(`                ${describeState(hop.state)}`);
    if (hop.failedChecks.length > 0) console.log(`                failed: ${hop.failedChecks.join(", ")}`);
    if (hop.advisoryGaps.length > 0) console.log(`                gaps:   ${hop.advisoryGaps.join(", ")}`);
  }
}
console.log(`overall    ${verdict.overallState}  (required: ${requested})`);
for (const mismatch of verdict.bindingMismatches) {
  console.log(`MISMATCH   ${mismatch.field}: asked for ${mismatch.expected}, ${mismatch.source} reported ${mismatch.observed}`);
}

if (!atLeast(verdict.overallState, requested)) {
  console.error(`\nNOT SENDING. The route reached ${verdict.overallState}, below ${requested}.`);
  if (verdict.reason) console.error(`Reason: ${verdict.reason}`);
  console.error("See VERIFYING.md for what each failed check means and what to do about it.");
  process.exit(1);
}
if (!verdict.gateway.requested) {
  // Worth saying out loud even on a pass.
  console.log("\nNOTE: hop 1 was not requested, so nothing here covers who routed the request.");
}

// ---- 2. Send, re-verifying hop 1 at send time -------------------------------

console.log(`\nOK: reached ${verdict.overallState}. Sending.`);

const reply = await client.chat({
  model: MODEL,
  provider: PROVIDER,
  messages: [{ role: "user", content: PROMPT }],
  maxOutputTokens: MAX_TOKENS,
  // The gate that actually protects this request. It runs BEFORE the first
  // authenticated call, so a caller who requires an attested plane has not spent
  // a ticket, or named a model, against one that is not.
  requireGateway: gateway
});

console.log(`\n${reply.content}`);
if (reply.usage) console.log(`\nusage: ${JSON.stringify(reply.usage)}`);
