// Verify both hops and interpret the result.
//
//   npx tsx examples/verify-route.ts
//
// Reads ANONROUTER_BASE_URL, ANONROUTER_API_KEY, and optionally
// ANONROUTER_MODEL / ANONROUTER_PROVIDER. Prints what was established, what was
// not, and why, then exits non-zero if the route did not meet the threshold.

import "./_env.js";
import { createClient, atLeast, describeState, type RouteVerificationState } from "../src/index.js";
import { createAnonRouterDcapVerifier } from "../src/gateway/dcap/index.js";

const BASE_URL = process.env.ANONROUTER_BASE_URL ?? "https://api.private.anonrouter.ai";
const CONTROL_URL = process.env.ANONROUTER_CONTROL_URL ?? "https://api.anonrouter.ai";
const MODEL = process.env.ANONROUTER_MODEL ?? "venice-uncensored";
const PROVIDER = process.env.ANONROUTER_PROVIDER ?? "venice";

// The bar this program insists on. `policy_matched` would accept a verdict that
// rests on a document we did not produce, which is weaker than most callers mean.
const REQUIRED: RouteVerificationState = "cryptographically_checked";

const apiKey = process.env.ANONROUTER_API_KEY;
if (!apiKey) {
  console.error("Set ANONROUTER_API_KEY to your AnonRouter API key (inference scope).");
  process.exit(2);
}

const client = createClient({ baseUrl: BASE_URL, controlBaseUrl: CONTROL_URL, apiKey });

const verdict = await client.verifyRoute({
  model: MODEL,
  provider: PROVIDER,
  // Ask about AnonRouter's own plane too and chain its quote to Intel.
  gateway: { chainVerifier: createAnonRouterDcapVerifier() }
});

console.log(`route      ${verdict.route.provider}/${verdict.route.model}`);
console.log(`modality   ${verdict.route.privacyModality}`
  + (verdict.contentVisibleToAnonRouter ? "  (AnonRouter sees your plaintext on this route)" : ""));
console.log();

for (const [name, hop] of [["hop 1 gateway ", verdict.gateway], ["hop 2 provider", verdict.provider]] as const) {
  const scope = hop.requested ? hop.state : "not requested";
  console.log(`${name}  ${scope}`);
  if (hop.requested) {
    console.log(`                ${describeState(hop.state)}`);
    if (hop.failedChecks.length > 0) console.log(`                failed: ${hop.failedChecks.join(", ")}`);
    if (hop.advisoryGaps.length > 0) console.log(`                gaps:   ${hop.advisoryGaps.join(", ")}`);
  }
}

console.log();
console.log(`overall    ${verdict.overallState}`);
if (verdict.bindingMismatches.length > 0) {
  // Two honestly-attested parties on the wrong route is still the wrong route.
  for (const m of verdict.bindingMismatches) {
    console.log(`MISMATCH   ${m.field}: asked for ${m.expected}, ${m.source} reported ${m.observed}`);
  }
}
if (verdict.reason) console.log(`reason     ${verdict.reason}`);

if (!atLeast(verdict.overallState, REQUIRED)) {
  console.error(`\nFAILED: route did not reach ${REQUIRED}.`);
  console.error("See VERIFYING.md for what each failed check means.");
  process.exit(1);
}
console.log(`\nOK: route reached ${REQUIRED}.`);
