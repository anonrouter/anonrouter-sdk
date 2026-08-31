#!/usr/bin/env node
// The anonrouter-verify cross-language gate.
//
// Both packages ship a command with the SAME NAME. If they ever printed
// different documents or returned different exit codes for the same inputs, a
// script written against one would silently mean something else under the other,
// which is worse than shipping only one of them.
//
// This runs both commands over inputs that need no network and no CVM, and
// requires the emitted JSON to be identical field for field, and the exit codes
// to match. The shared vectors already pin the SHAPE from inside each test suite;
// this pins the actual OUTPUT of the actual executables, which is the thing a
// user runs.
//
//   node scripts/check-cli-parity.mjs
//
// Exit 0 parity holds, 1 it does not, 2 one of the two commands is not runnable
// here (skipped with a stated reason rather than passing quietly).

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const jsCli = resolve(root, "js/confidential/dist/cli.js");

/** Cases that reach a verdict without a network call or a confidential VM. */
const CASES = [
  { name: "doctor, no origin", argv: ["doctor", "--compact"] },
  { name: "doctor, an origin this package pins", argv: ["doctor", "--origin", "https://api.private.anonrouter.ai", "--compact"] },
  { name: "doctor, an origin it does not", argv: ["doctor", "--origin", "https://example.invalid", "--compact"] },
  {
    name: "gateway against an unpinned origin (fails closed offline)",
    argv: ["gateway", "--origin", "https://nothing-is-pinned-for-this.example", "--compact"],
    // The one field that legitimately differs: each language's refusal names its
    // OWN api (`policy option` / `policy=`), and making either name the other's
    // would be worse than tolerating the difference.
    ignore: ["outcome.reason", "gateway.reason"]
  }
];

function runJs(argv) {
  return run(process.execPath, [jsCli, ...argv]);
}

function runPython(python, argv) {
  return run(python, ["-m", "anonrouter_confidential.cli", ...argv]);
}

function run(command, args) {
  try {
    const stdout = execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, stdout };
  } catch (error) {
    // A nonzero exit is an expected outcome here, not a failure to run.
    if (typeof error.status === "number") return { code: error.status, stdout: String(error.stdout ?? "") };
    throw error;
  }
}

/** Locate a Python that can import the package, or explain why none can. */
function findPython() {
  const candidates = [process.env.ANONROUTER_PYTHON, "python3", "python"].filter(Boolean);
  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ["-c", "import anonrouter_confidential.cli"], { stdio: "ignore" });
      return candidate;
    } catch { /* try the next one */ }
  }
  return null;
}

function omit(value, paths, prefix = "") {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const out = {};
  for (const [key, entry] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (paths.includes(path)) continue;
    out[key] = omit(entry, paths, path);
  }
  return out;
}

function differences(a, b, path = "") {
  const out = [];
  const keys = new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})]);
  for (const key of keys) {
    const here = path ? `${path}.${key}` : key;
    const left = a?.[key];
    const right = b?.[key];
    if (left && right && typeof left === "object" && typeof right === "object" && !Array.isArray(left)) {
      out.push(...differences(left, right, here));
    } else if (JSON.stringify(left) !== JSON.stringify(right)) {
      out.push(`${here}: js=${JSON.stringify(left)} python=${JSON.stringify(right)}`);
    }
  }
  return out;
}

if (!existsSync(jsCli)) {
  console.error(`SKIPPED: ${jsCli} does not exist. Run \`npm run build\` in js/ first.`);
  process.exit(2);
}
const python = findPython();
if (!python) {
  console.error("SKIPPED: no Python on PATH can import anonrouter_confidential.cli.");
  console.error("Install it with `pip install -e ./python`, or set ANONROUTER_PYTHON.");
  process.exit(2);
}

let failures = 0;
for (const testCase of CASES) {
  const js = runJs(testCase.argv);
  const py = runPython(python, testCase.argv);

  if (js.code !== py.code) {
    console.error(`FAIL ${testCase.name}: exit codes differ (js=${js.code} python=${py.code})`);
    failures += 1;
    continue;
  }

  let jsDocument;
  let pyDocument;
  try {
    jsDocument = JSON.parse(js.stdout);
    pyDocument = JSON.parse(py.stdout);
  } catch {
    console.error(`FAIL ${testCase.name}: one command did not print parseable JSON`);
    failures += 1;
    continue;
  }

  const ignore = testCase.ignore ?? [];
  const diff = differences(omit(jsDocument, ignore), omit(pyDocument, ignore));
  if (diff.length > 0) {
    console.error(`FAIL ${testCase.name}: ${diff.length} field(s) differ`);
    for (const entry of diff) console.error(`    ${entry}`);
    failures += 1;
  } else {
    console.log(`ok: ${testCase.name} (exit ${js.code}, documents identical${ignore.length ? `, ignoring ${ignore.join(", ")}` : ""})`);
  }
}

if (failures > 0) {
  console.error(`\nanonrouter-verify has drifted between the two languages in ${failures} case(s).`);
  process.exit(1);
}
console.log("\nanonrouter-verify prints the same document in both languages.");
