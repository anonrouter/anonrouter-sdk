#!/usr/bin/env node
// The cross-language drift gate. Fails (exit 1) if any per-package copy of a
// shared pin file has drifted from its canonical file under shared/. Run in CI on
// every PR. (The known-answer-vector parity between JS and Python runs in each
// language's own test suite against shared/vectors/*; this script guards the pins.)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { SYNCED_FILES } from "./shared-files.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

let drift = 0;
for (const [canonicalRel, copies] of Object.entries(SYNCED_FILES)) {
  let canonicalStr;
  try {
    canonicalStr = JSON.stringify(JSON.parse(readFileSync(resolve(root, canonicalRel), "utf8")));
  } catch {
    console.error(`MISSING or unparseable canonical file: ${canonicalRel}`);
    drift += 1;
    continue;
  }
  for (const rel of copies) {
    let copy;
    try {
      copy = JSON.parse(readFileSync(resolve(root, rel), "utf8"));
    } catch {
      console.error(`MISSING or unparseable: ${rel} (run: node scripts/sync-shared.mjs)`);
      drift += 1;
      continue;
    }
    if (JSON.stringify(copy) !== canonicalStr) {
      console.error(`DRIFT: ${rel} does not match ${canonicalRel} (run: node scripts/sync-shared.mjs)`);
      drift += 1;
    } else {
      console.log(`ok: ${rel}`);
    }
  }
}

if (drift > 0) {
  console.error(`\npin drift detected in ${drift} file(s).`);
  process.exit(1);
}
console.log("\nAll shared pin copies are in sync with shared/.");
