// Independently verify a TEE (or E2EE) route against the REAL AnonRouter gateway,
// using YOUR API key. This runs OUR verifier over the raw enclave evidence and does
// not simply trust the gateway's verdict. It is attestation only, so it is NOT a
// billable inference call.
//
// Run (from js/confidential):
//   ANONROUTER_API_KEY=ar_... npm run example:verify-tee
// Optional env:
//   ANONROUTER_BASE_URL   default https://api.anonrouter.ai
//   ANONROUTER_CONTROL_URL default https://control.anonrouter.ai
//   TEE_MODEL             default openai/gpt-oss-120b
//   TEE_PROVIDER          default tinfoil   (try: tinfoil | venice | chutes)

import "./_env.js";
import { createClient } from "../src/index.js";

const apiKey = process.env.ANONROUTER_API_KEY;
if (!apiKey) {
  console.error("Set ANONROUTER_API_KEY to your AnonRouter API key (inference scope).");
  process.exit(2);
}
const baseUrl = process.env.ANONROUTER_BASE_URL ?? "https://api.anonrouter.ai";
const controlBaseUrl = process.env.ANONROUTER_CONTROL_URL ?? "https://control.anonrouter.ai";
const model = process.env.TEE_MODEL ?? "openai/gpt-oss-120b";
const provider = process.env.TEE_PROVIDER ?? "tinfoil";

const client = createClient({ baseUrl, controlBaseUrl, apiKey });

const res = await client.verifyAttestation({ model, provider });

console.log(`\nRoute:            ${provider} / ${model}`);
console.log(`Gateway:          ${baseUrl}`);
console.log(`Privacy modality: ${res.privacyModality}   (tee = enclave-verified; e2ee = also client-encrypted)`);
console.log(`\nOUR independent verdict: ${res.verdict.status} / ${res.verdict.verification_level}`);
if (res.gatewayVerdict) {
  console.log(`Gateway verdict:         ${res.gatewayVerdict.status} / ${res.gatewayVerdict.verification_level}`);
}

console.log("\nChecks:");
for (const c of res.verdict.checks) {
  const mark = c.passed ? "PASS" : c.required ? "FAIL" : "warn";
  const tag = c.required ? "" : " (advisory)";
  const detail = c.detail ? `: ${c.detail}` : "";
  console.log(`  ${mark}  ${c.name}${tag}${detail}`);
}

const measurements = Object.entries(res.verdict.measurement_identities ?? {});
if (measurements.length > 0) {
  console.log("\nReviewed measurements it matched:");
  for (const [name, value] of measurements) console.log(`  ${name}: ${value}`);
}

const ok = res.verdict.status === "ok";
console.log(ok
  ? "\nVERIFIED independently. The raw evidence checks out against the reviewed pins, not just the gateway's word."
  : "\nNOT verified. See the failing checks above.");
process.exit(ok ? 0 : 1);
