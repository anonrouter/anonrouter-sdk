#!/usr/bin/env node
// Capture a gateway's CURRENTLY OBSERVED identity into a candidate file for review.
//
// This deliberately does NOT write a policy, and it never edits
// shared/gateway-policies.json. A policy taken from the server it describes is
// circular: a gateway that could hand you the list of builds you accept could
// always name itself. What this produces is an OBSERVATION, which is the input to
// a review, not its output.
//
// The review that has to happen before any of these values become a pin:
//
//   app_id, compose_hash, os_image_hash
//       must appear in an independently produced identity record for THIS ORIGIN
//       (in the product repo, .evidence/content-plane/pinned-identity.json), and
//       that record must not be a preproduction one.
//   release_id
//       is an operator-supplied string injected at deploy time. It proves only
//       that whoever deployed set it. Confirm it names a build you reviewed.
//   mrTd, rtmr0..2
//       reproduce offline with dstack-mr from the OS image and vm_config. Do not
//       copy them from a running machine.
//   tls_spki_sha256
//       compare against the certificate actually served on the origin you intend
//       to pin, observed yourself, not the one recorded for another hostname.
//
// Usage:
//   node scripts/capture-gateway-pins.mjs https://your-cvm.example [--out FILE]

import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const args = process.argv.slice(2);
const origin = args.find((a) => !a.startsWith("--"));
const outIndex = args.indexOf("--out");
const outPath = outIndex >= 0 ? args[outIndex + 1] : null;

if (!origin) {
  console.error("usage: node scripts/capture-gateway-pins.mjs <origin> [--out FILE]");
  process.exit(2);
}

const nonce = createHash("sha256").update(String(process.hrtime.bigint()) + Math.random()).digest("hex");

const response = await fetch(`${origin.replace(/\/+$/, "")}/v1/gateway/attestation?nonce=${nonce}`, {
  headers: { accept: "application/json" }
}).catch((error) => {
  console.error(`could not reach ${origin}: ${error.message}`);
  process.exit(1);
});

if (response.status === 404 || response.status === 503) {
  console.error(`${origin} does not expose gateway attestation (status ${response.status}).`);
  console.error("There is nothing to capture: this deployment is not an attestable CVM.");
  process.exit(1);
}
if (!response.ok) {
  console.error(`${origin} returned ${response.status}`);
  process.exit(1);
}

const doc = await response.json();
const binding = doc?.binding;
if (!binding || typeof binding !== "object") {
  console.error("response carried no binding");
  process.exit(1);
}
// Sanity: the document must at least be bound to the nonce we just sent, or we
// captured a replay and the observation is worthless.
if (binding.nonce !== nonce) {
  console.error("the returned document is not bound to our nonce; refusing to capture a replay");
  process.exit(1);
}

const quote = Buffer.from(String(doc.quote), "hex");
const at = (off) => quote.subarray(off, off + 48).toString("hex");

const observation = {
  $schema: "anonrouter-gateway-pin-observation-v1",
  $warning: [
    "OBSERVED VALUES, NOT A POLICY. Nothing here is reviewed.",
    "Do not paste these into shared/gateway-policies.json.",
    "Each field must first be corroborated by an independently produced record",
    "for THIS origin. See the header of scripts/capture-gateway-pins.mjs."
  ],
  observedAt: new Date().toISOString(),
  origin,
  observed: {
    appId: binding.app_id,
    instanceId: binding.instance_id,
    composeHash: binding.compose_hash,
    releaseId: binding.release_id,
    originClaimed: binding.origin,
    transport: binding.transport,
    tlsSpkiSha256: binding.tls_spki_sha256,
    osImageHash: doc?.info?.os_image_hash ?? null,
    platform: {
      mrTd: at(184),
      mrConfigId: at(232),
      rtmr0: at(376),
      rtmr1: at(424),
      rtmr2: at(472)
    }
  },
  reviewChecklist: {
    identityRecordForThisOrigin: "UNVERIFIED - find a non-preproduction record naming this exact origin",
    releaseIdNamesAReviewedBuild: "UNVERIFIED - release_id is an operator-set env value, not a measurement",
    platformReproducedWithDstackMr: "UNVERIFIED - recompute offline, do not copy from the machine",
    servedCertificateMatchesBinding: "UNVERIFIED - observe the cert on this origin yourself"
  }
};

const serialized = JSON.stringify(observation, null, 2) + "\n";
if (outPath) {
  writeFileSync(outPath, serialized);
  console.error(`wrote observation to ${outPath}`);
} else {
  process.stdout.write(serialized);
}
console.error("");
console.error("This is an OBSERVATION. It is not a pin and must not be copied into a policy");
console.error("until every reviewChecklist entry is resolved against independent evidence.");
