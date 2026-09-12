#!/usr/bin/env node
// Build every artifact a release publishes, and write one SHA256SUMS over all of
// them.
//
//   node scripts/build-release-artifacts.mjs [--no-dcap]
//
// The same script runs locally and in the release workflow, so "it worked on my
// machine" and "it worked in CI" are the same claim rather than two. Output goes
// to dist/artifacts/.
//
// WHAT IS PRODUCED
//
//   anonrouter-sdk-<version>-source.tar.gz   git archive of the tagged tree
//   anonrouter-confidential-<version>.tgz    npm pack
//   anonrouter-client-<version>.tgz          npm pack
//   anonrouter_confidential-<version>-py3-none-any.whl
//   anonrouter_confidential-<version>.tar.gz
//   anonrouter-dcap-verifier-linux-amd64     reproducible, see build-dcap-verifier.sh
//   anonrouter-dcap-verifier-src-<version>.tar.gz   its AGPL source, shipped WITH it
//   SHA256SUMS                               every file above
//
// DETERMINISM. The tarballs are built with SOURCE_DATE_EPOCH derived from the
// commit rather than from the clock, and `git archive` is given an explicit
// mtime for the same reason: an artifact whose digest depends on WHEN it was
// built cannot be compared with anyone else's.
//
// The DCAP verifier's source ships next to the binary because that binary is
// AGPL-3.0-only. Distributing it without the corresponding source would be a
// licence violation, and would also make the word "reproducible" hollow: there
// would be nothing for a third party to rebuild.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, copyFileSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist", "artifacts");
const skipDcap = process.argv.includes("--no-dcap");
const python = process.env.ANONROUTER_PYTHON || "python3";

const VERSION = JSON.parse(readFileSync(join(root, "js", "confidential", "package.json"), "utf8")).version;

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], ...options });
}

// Derived from the commit, never the clock. Falls back to a fixed value outside a
// git checkout so an extracted source tree still builds deterministically.
let epoch = "0";
try {
  epoch = run("git", ["-C", root, "log", "-1", "--format=%ct"]).trim() || "0";
} catch { /* not a git checkout */ }
const isoEpoch = new Date(Number(epoch) * 1000).toISOString();

mkdirSync(out, { recursive: true });
// Never let a stale artifact from an earlier version ride along into SHA256SUMS.
for (const name of readdirSync(out)) rmSync(join(out, name), { recursive: true, force: true });

const produced = [];
function record(path) {
  produced.push(path);
  const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
  console.log(`  ${digest}  ${basename(path)}`);
}

// ---- 1. Reviewable source ----------------------------------------------------
console.log("source archive");
const sourceName = `anonrouter-sdk-${VERSION}-source.tar.gz`;
run("git", [
  "-C", root, "archive",
  "--format=tar.gz",
  `--prefix=anonrouter-sdk-${VERSION}/`,
  `--mtime=${isoEpoch}`,
  "-o", join(out, sourceName),
  "HEAD"
]);
record(join(out, sourceName));

// ---- 2. npm tarballs ---------------------------------------------------------
console.log("npm packages");
run("npm", ["run", "build"], { cwd: join(root, "js") });
for (const pkg of ["confidential", "client"]) {
  const packed = run("npm", ["pack", "--pack-destination", out, "--silent"], {
    cwd: join(root, "js", pkg),
    env: { ...process.env, SOURCE_DATE_EPOCH: epoch }
  }).trim().split("\n").pop().trim();
  record(join(out, packed));
}

// ---- 3. Python distributions -------------------------------------------------
console.log("python distributions");
run(python, ["-m", "build", "--outdir", out], {
  cwd: join(root, "python"),
  env: { ...process.env, SOURCE_DATE_EPOCH: epoch }
});
for (const name of readdirSync(out)) {
  if (name.startsWith("anonrouter_confidential-")) record(join(out, name));
}

// ---- 4. The DCAP verifier, with its source -----------------------------------
if (skipDcap) {
  console.log("dcap verifier: SKIPPED (--no-dcap)");
} else {
  console.log("dcap verifier");
  run("bash", [join(root, "scripts", "build-dcap-verifier.sh"), "--reproduce"], {
    env: { ...process.env, DCAP_OUT_DIR: out },
    stdio: ["ignore", "inherit", "inherit"]
  });
  record(join(out, "anonrouter-dcap-verifier-linux-amd64"));

  const srcName = `anonrouter-dcap-verifier-src-${VERSION}.tar.gz`;
  run("git", [
    "-C", root, "archive",
    "--format=tar.gz",
    `--prefix=anonrouter-dcap-verifier-${VERSION}/`,
    `--mtime=${isoEpoch}`,
    "-o", join(out, srcName),
    "HEAD", "native/dcap-verifier"
  ]);
  record(join(out, srcName));
}

// ---- 5. One checksum file over everything ------------------------------------
const lines = produced
  .map((path) => `${createHash("sha256").update(readFileSync(path)).digest("hex")}  ${basename(path)}`)
  .sort();
writeFileSync(join(out, "SHA256SUMS"), `${lines.join("\n")}\n`);

console.log(`\n${produced.length} artifacts in dist/artifacts, checksummed in SHA256SUMS`);
console.log(`version ${VERSION}, SOURCE_DATE_EPOCH ${epoch} (${isoEpoch})`);

if (!existsSync(join(out, "SHA256SUMS"))) process.exit(1);
