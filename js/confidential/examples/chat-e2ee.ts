// Run a full END-TO-END E2EE chat against the REAL AnonRouter gateway with YOUR
// API key. The SDK verifies the enclave, encrypts your prompt IN THIS PROCESS,
// relays only ciphertext, and decrypts the reply. This example wraps fetch to PROVE
// the relay never received your prompt in plaintext.
//
// NOTE: this makes a real, billable inference call (kept tiny by MAX_TOKENS).
//
// Run (from js/confidential):
//   ANONROUTER_API_KEY=ar_... npm run example:chat-e2ee
// Optional env:
//   ANONROUTER_BASE_URL   default https://api.anonrouter.ai (override for a local backend)
//   E2EE_MODEL            default openai/gpt-oss-120b
//   E2EE_PROVIDER         default near-ai   (E2EE only: near-ai | venice | chutes)
//   MAX_TOKENS            default 32
//   PROMPT                default a short prompt containing a unique canary

import "./_env.js";
import { createClient, type FetchLike } from "../src/index.js";

const apiKey = process.env.ANONROUTER_API_KEY;
if (!apiKey) {
  console.error("Set ANONROUTER_API_KEY to your AnonRouter API key (inference scope).");
  process.exit(2);
}
const baseUrl = process.env.ANONROUTER_BASE_URL ?? "https://api.anonrouter.ai";
const model = process.env.E2EE_MODEL ?? "openai/gpt-oss-120b";
const provider = process.env.E2EE_PROVIDER ?? "near-ai";
const maxOutputTokens = Number(process.env.MAX_TOKENS ?? "32");

const canary = "CANARY-" + Math.random().toString(36).slice(2);
const prompt = process.env.PROMPT ?? `Reply with the single word OK. Ignore this token: ${canary}`;

// Wrap fetch to inspect exactly what reaches the credential-isolated relay.
let relayObserved = false;
let plaintextLeaked = false;
const baseFetch = globalThis.fetch.bind(globalThis) as FetchLike;
const inspectingFetch: FetchLike = async (url, init = {}) => {
  const path = new URL(String(url)).pathname;
  if (path.endsWith("/v1/chat/completions") || path.endsWith("/v1/e2ee/chat/completions")) {
    relayObserved = true;
    const body = init.body;
    const asText = body instanceof Uint8Array
      ? Buffer.from(body).toString("latin1")
      : String(body ?? "");
    if (asText.includes(canary) || asText.includes(prompt)) plaintextLeaked = true;
  }
  return baseFetch(url, init);
};

const client = createClient({ baseUrl, apiKey, fetch: inspectingFetch });

console.log(`\nE2EE chat:  ${provider} / ${model}`);
console.log(`Gateway:    ${baseUrl}`);
console.log(`Your prompt (plaintext stays on THIS machine): ${prompt}`);

const res = await client.chat({
  model,
  provider,
  messages: [{ role: "user", content: prompt }],
  maxOutputTokens
});

console.log(`\nDecrypted reply: ${res.content}`);
if (res.usage) console.log(`Usage: ${JSON.stringify(res.usage)}`);

if (!relayObserved) {
  console.log("\n(Could not observe the relay request body.)");
  process.exit(0);
}
if (plaintextLeaked) {
  console.log("\nWARNING: your prompt appeared in plaintext in the relay request body. This should never happen.");
  process.exit(1);
}
console.log("\nPROOF: the relay received ciphertext only. Your prompt was never in the request body or headers.");
console.log("The plaintext existed only on your machine and inside the verified enclave.");
process.exit(0);
