#!/usr/bin/env node
// Preparation/assembly ONLY. Never reads a signing key or publishes anything.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalGatewayPolicyJson, packagedGatewayPolicyAuthority, GATEWAY_POLICY_DOMAIN,
  verifySignedGatewayPolicy, assertGatewayPolicySecurityFloor
} from "../js/confidential/dist/gateway/authority.js";
import { loadGatewayPolicy } from "../js/confidential/dist/gateway/policy.js";

export function prepareGatewayPolicyRelease(manifestBytes, policyDocument, sequence, issuedAtMs, expiresAtMs) {
  const root = packagedGatewayPolicyAuthority();
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const policy = loadGatewayPolicy(policyDocument);
  assertGatewayPolicySecurityFloor(policy);
  // A tuple-form policy can name several releases, but a retained manifest names
  // one. Its correlation procedure is not reviewed yet, and gcp-tdx-native is not
  // qualified for signed approval at all, so refuse rather than half-check it.
  if (policy.platformKind !== undefined) throw new Error("tuple-form policy approval preparation is not supported yet");
  const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
  if (manifest.schema !== "anonrouter.release-manifest/v2" || manifest.status !== "live-hardware-measurement"
    || manifest.source?.dirty !== false || manifest.deployment?.transport !== "in-tee-tls") throw new Error("a retained finalized clean hardware/TLS manifest is required");
  if (policy.source !== `anonrouter-release-manifest-sha256:${manifestSha256}`
    || policy.appIds.length !== 1 || policy.appIds[0] !== manifest.deployment.app_id
    || policy.composeHashes.length !== 1 || policy.composeHashes[0] !== manifest.compose?.measured_hash
    || policy.releaseIds.length !== 1 || policy.releaseIds[0] !== manifest.release_id
    || !policy.origins.includes(manifest.deployment.origin)
    || policy.origins.some(o => !root.origins.includes(o))
    || policy.platform.osImageHash.length !== 1 || policy.platform.osImageHash[0] !== manifest.deployment.os_image_hash) throw new Error("policy disagrees with independently retained manifest");
  if (!Number.isSafeInteger(sequence) || sequence < root.minSequence
    || !Number.isSafeInteger(issuedAtMs) || !Number.isSafeInteger(expiresAtMs)
    || issuedAtMs < 0 || expiresAtMs <= issuedAtMs || expiresAtMs-issuedAtMs > root.maxLifetimeMs) throw new Error("invalid sequence or validity window");
  // Preserve the validated wire schema, never serialize TypeScript-only fields.
  const payload = canonicalGatewayPolicyJson({ schema: "anonrouter.gateway-policy/v1", authority: root.authority,
    sequence, issuedAtMs, expiresAtMs, manifestSha256, policy: policyDocument });
  return { payload, signingBytes: GATEWAY_POLICY_DOMAIN + payload };
}
export function assembleGatewayPolicyRelease(payload, signatures, nowMs = Date.now()) {
  const root = packagedGatewayPolicyAuthority();
  const envelope = { schema: "anonrouter.gateway-policy-envelope/v1", payload, signatures };
  // All intended origins must pass, not merely the canonical hostname.
  for (const origin of root.origins) verifySignedGatewayPolicy(envelope, root, origin, nowMs);
  return envelope;
}
function main(args) {
  const command = args.shift(); const options = new Map();
  if (args.length % 2) throw new Error("options require values");
  for (let i=0;i<args.length;i+=2) {
    if (!args[i].startsWith("--") || options.has(args[i])) throw new Error("unknown/duplicate option");
    options.set(args[i], args[i+1]);
  }
  const required = name => { if (!options.has(name)) throw new Error(`${name} is required`); return options.get(name); };
  const allowed = command === "prepare"
    ? ["--manifest","--policy","--sequence","--issued-at-ms","--expires-at-ms","--out"]
    : command === "assemble" ? ["--payload","--signatures","--out"] : ["--envelope"];
  if ([...options.keys()].some(k=>!allowed.includes(k))) throw new Error("unknown option");
  if (command === "prepare") {
    const result = prepareGatewayPolicyRelease(readFileSync(required("--manifest")), JSON.parse(readFileSync(required("--policy"),"utf8")),
      Number(required("--sequence")), Number(required("--issued-at-ms")), Number(required("--expires-at-ms")));
    const path = required("--out");
    writeFileSync(path, result.payload, {flag:"wx",mode:0o644});
    writeFileSync(path+".signing-bytes",result.signingBytes,{flag:"wx",mode:0o644});
    process.stdout.write("Prepared unsigned policy and purpose-specific signing bytes. No signature or publication performed.\n");
  } else if (command === "assemble") {
    const envelope = assembleGatewayPolicyRelease(readFileSync(required("--payload"),"utf8"),JSON.parse(readFileSync(required("--signatures"),"utf8")));
    writeFileSync(required("--out"),JSON.stringify(envelope)+"\n",{flag:"wx",mode:0o644});
    process.stdout.write("Assembled policy; both production origins verified against packaged custodian roots. Not published.\n");
  } else if (command === "verify") {
    const root=packagedGatewayPolicyAuthority(); const envelope=JSON.parse(readFileSync(required("--envelope"),"utf8"));
    for(const origin of root.origins) verifySignedGatewayPolicy(envelope,root,origin,Date.now());
    process.stdout.write("Verified signed gateway policy for both production origins.\n");
  } else throw new Error("usage: gateway-policy-release.mjs prepare|assemble|verify (see docs/gateway-policy-updates.md)");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch { process.stderr.write("Gateway-policy release refused; check arguments, retained artifacts and required signatures.\n"); process.exitCode=1; }
}
