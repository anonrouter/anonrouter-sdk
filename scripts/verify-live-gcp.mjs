#!/usr/bin/env node
// Read-only and credential-free. No tickets, prompts or inference requests.
// Build js/ first, or set ANONROUTER_SDK_MODULE to an installed dist/index.js URL.
import assert from "node:assert/strict";
const moduleUrl = process.env.ANONROUTER_SDK_MODULE ?? new URL("../js/confidential/dist/index.js", import.meta.url).href;
const sdk = await import(moduleUrl);
const dcapUrl = new URL("./gateway/dcap/index.js", moduleUrl).href;
const { createAnonRouterDcapVerifier } = await import(dcapUrl);
const source = sdk.createReleasePolicyV3Source();
const origin = "https://api.anonrouter.ai";
const approval = await source.resolve(origin);
const chainFactory = createAnonRouterDcapVerifier();
const result = await sdk.verifyContentNode({ policySource: source, chainVerifier: chainFactory,
  signal: AbortSignal.timeout(60_000) });
assert.equal(result.verdict.status, "ok");
assert.equal(result.verdict.verificationLevel, "hardware-verified");
assert.equal(result.verdict.tcbStatus, "UpToDate");
assert.equal(result.policy.sequence, approval.sequence, "feed changed during probe; rerun against one policy");
const evidence = result.rawEvidence;
const chainVerifier = await chainFactory.prepare(evidence.quote, { acceptedTcbStatuses: ["UpToDate"] });
const expected = { policy: approval.policy, nonce: evidence.binding.nonce, origin,
  observedTlsSpkiSha256: evidence.binding.tls_spki_sha256, observedOnRetainedConnection: true, chainVerifier };
const negatives = [];
for (const [name, overrides, failure] of [
  ["wrong nonce", { nonce: "00".repeat(32) }, "nonce_matches_request"],
  ["wrong origin", { origin: "https://wrong.example" }, "origin_matches_connection"],
  ["wrong observed TLS key", { observedTlsSpkiSha256: "00".repeat(32) }, "tls_certificate_bound_to_quote"],
  ["separate connection", { observedOnRetainedConnection: false }, "tls_observed_on_retained_connection"]
]) {
  const verdict = sdk.verifyGatewayAttestation(evidence, { ...expected, ...overrides });
  assert.equal(verdict.status, "failed", name);
  assert(verdict.checks.some(c => c.name === failure && c.required && !c.passed), name);
  negatives.push(name);
}
const root = sdk.packagedReleasePolicyV3Authority();
const response = await fetch(root.url, { credentials: "omit", redirect: "error", signal: AbortSignal.timeout(10_000) });
assert(response.ok);
const envelope = await response.json();
envelope.signatures[0].signature = "00".repeat(64);
assert.throws(() => sdk.verifyReleasePolicyV3(envelope, root.trust), /signature_invalid/);
negatives.push("tampered owner signature");
console.log(JSON.stringify({ status: result.verdict.status, level: result.verdict.verificationLevel,
  tcbStatus: result.verdict.tcbStatus, policy: result.policy,
  nonce: evidence.binding.nonce, instanceIdentity: result.verdict.instanceIdentity,
  requiredChecksPassed: result.verdict.checks.filter(c => c.required && c.passed).length,
  advisoryGaps: result.verdict.checks.filter(c => !c.required && !c.passed).map(c => c.name),
  negativesRefused: negatives }, null, 2));
