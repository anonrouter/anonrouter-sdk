#!/usr/bin/env node
// Refresh the Chutes TEE measurement pin from Chutes' PUBLISHED measurement list.
//
// Chutes ships many enclave configs and rotates them often, so its pin drifts more
// than any other provider. This tool fetches api.chutes.ai/servers/tee/measurements,
// rebuilds the accepted allowlist (one entry per published config, using the RUNTIME
// RTMRs a live TDX quote presents), and UNIONS it with whatever is already pinned so
// a config that is currently serving is never dropped even if Chutes unpublishes it.
//
// Trust note: adopting the whole published list moves the Chutes trust boundary from
// "an operator reviewed this exact enclave" to "we trust Chutes' published list". That
// is a deliberate choice. This script defaults to a DRY RUN that only prints the diff;
// pass --apply to write. Broadening the set stays a reviewed action.
//
// Usage (from repo root):
//   node scripts/refresh-chutes-pins.mjs                # dry run: show the diff
//   node scripts/refresh-chutes-pins.mjs --apply        # write shared/measurements.json
//
// After --apply, run:  node scripts/sync-shared.mjs && node scripts/check-parity.mjs
//
// Env:
//   CHUTES_MEASUREMENTS_URL  default https://api.chutes.ai/servers/tee/measurements

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sharedPath = resolve(root, "shared/measurements.json");
const url = process.env.CHUTES_MEASUREMENTS_URL ?? "https://api.chutes.ai/servers/tee/measurements";

const apply = process.argv.includes("--apply");

const norm = (s) => String(s).toLowerCase();
const keyOf = (e) => [e.mrTd, e.rtmr0, e.rtmr1, e.rtmr2, e.rtmr3].join("|");

function die(msg) {
  console.error(`refresh-chutes-pins: ${msg}`);
  process.exit(1);
}

// 1) Fetch published measurements.
let published;
try {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) die(`fetch ${url} -> HTTP ${res.status}`);
  published = await res.json();
} catch (err) {
  die(`could not fetch ${url}: ${err?.message ?? err}`);
}
if (!Array.isArray(published) || published.length === 0) die("published measurements are not a non-empty array");

// 2) Build one pin entry per published config, using RUNTIME rtmrs.
const pubEntries = published.map((e, i) => {
  const rt = e.runtime_rtmrs ?? {};
  for (const k of ["mrtd", "name", "version"]) if (e[k] == null) die(`published entry ${i} missing ${k}`);
  for (const k of ["RTMR0", "RTMR1", "RTMR2", "RTMR3"]) if (rt[k] == null) die(`published entry ${i} missing runtime_rtmrs.${k}`);
  return {
    name: `${e.name} [v${e.version}]`,
    mrTd: norm(e.mrtd),
    rtmr0: norm(rt.RTMR0),
    rtmr1: norm(rt.RTMR1),
    rtmr2: norm(rt.RTMR2),
    rtmr3: norm(rt.RTMR3)
  };
});

// 3) Union with the current pin (never drop a serving config).
const shared = JSON.parse(readFileSync(sharedPath, "utf8"));
const current = shared.providers?.chutes?.measurementPolicy?.accepted ?? [];
const currentKeys = new Set(current.map(keyOf));
const pubKeys = new Set(pubEntries.map(keyOf));

const merged = [...pubEntries];
const carried = [];
for (const e of current) {
  if (!pubKeys.has(keyOf(e))) { merged.push(e); carried.push(e); }
}

const added = pubEntries.filter((e) => !currentKeys.has(keyOf(e)));

// 4) Report the diff.
console.log(`source:    ${url}`);
console.log(`published: ${pubEntries.length}   currently pinned: ${current.length}   merged total: ${merged.length}`);
console.log(`ADDED (new in published, not yet pinned): ${added.length}`);
for (const e of added) console.log(`  + ${e.name.padEnd(40)} ${e.rtmr0.slice(0, 16)}...`);
console.log(`CARRIED (pinned but no longer published, kept): ${carried.length}`);
for (const e of carried) console.log(`  = ${e.name.padEnd(40)} ${e.rtmr0.slice(0, 16)}...`);

if (added.length === 0 && carried.length === 0 && merged.length === current.length) {
  console.log("\nPin already matches the published list. Nothing to do.");
  process.exit(0);
}

if (!apply) {
  console.log("\nDry run. Re-run with --apply to write shared/measurements.json.");
  process.exit(0);
}

// 5) Apply to the canonical shared file.
const stamp = new Date().toISOString().slice(0, 10);
const version = `chutes-published-full-${stamp}`;
shared.providers.chutes.measurementPolicy.version = version;
shared.providers.chutes.measurementPolicy.note =
  "Full published Chutes measurement set (api.chutes.ai/servers/tee/measurements). " +
  "Trust boundary for Chutes is its published list rather than per-config operator " +
  "review; regenerate with scripts/refresh-chutes-pins.mjs when Chutes rotates.";
shared.providers.chutes.measurementPolicy.accepted = merged;
writeFileSync(sharedPath, JSON.stringify(shared, null, 2) + "\n");
console.log(`\nwrote ${sharedPath.replace(root + "/", "")}  (version ${version})`);
console.log("next: node scripts/sync-shared.mjs && node scripts/check-parity.mjs");
