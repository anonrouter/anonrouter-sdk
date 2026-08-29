#!/usr/bin/env node
// Copy the canonical shared pin files into each language package so they can be
// bundled/published, and normalize formatting. The files under shared/ are the
// SINGLE SOURCE OF TRUTH; the per-package copies are generated. check-parity.mjs
// fails CI if a copy drifts from its canonical file.
//
//   measurements.json      pins for the UPSTREAM provider enclaves (hop 2)
//   gateway-policies.json  pins for AnonRouter's own confidential plane (hop 1)

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { SYNCED_FILES } from "./shared-files.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

for (const [canonicalRel, targets] of Object.entries(SYNCED_FILES)) {
  const canonical = JSON.parse(readFileSync(resolve(root, canonicalRel), "utf8"));
  const serialized = JSON.stringify(canonical, null, 2) + "\n";
  for (const target of targets) {
    writeFileSync(resolve(root, target), serialized);
    console.log(`synced ${canonicalRel} -> ${target}`);
  }
}
