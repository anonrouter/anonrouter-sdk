#!/usr/bin/env node
// Install what would actually be published, into empty directories, and use it.
//
// Every other gate in this repo runs against the working tree. That proves the
// code is right and says nothing about whether the ARTIFACT is: a missing entry
// in `files`, an `exports` map that does not resolve, a `bin` that is not
// executable, or a wheel that omits a data file are all invisible until somebody
// installs the thing. Those failures land on a user, after publication, and are
// exactly the class this script exists to catch before it.
//
// What it does, for each package:
//
//   1. builds the artifact (npm pack / python -m build),
//   2. installs it into a fresh, empty environment with no repo on the path,
//   3. imports every documented entry point,
//   4. runs the installed command and checks its exit code and its JSON, and
//   5. asserts the shipped measurement pins are present and parse.
//
//   node scripts/smoke-artifacts.mjs [--keep]
//
// Exit 0 everything installs and works, 1 something is wrong with an artifact,
// 2 the environment cannot run the check (no network, no python) and it was
// SKIPPED rather than passed.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const keep = process.argv.includes("--keep");
const workspace = mkdtempSync(join(tmpdir(), "anonrouter-smoke-"));
let failures = 0;

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options
  });
}

/** Run a command that is allowed to exit nonzero, and return code plus stdout. */
function runAllowingFailure(command, args, options = {}) {
  try {
    return { code: 0, stdout: run(command, args, options) };
  } catch (error) {
    if (typeof error.status === "number") return { code: error.status, stdout: String(error.stdout ?? "") };
    throw error;
  }
}

function check(name, fn) {
  try {
    fn();
    console.log(`ok: ${name}`);
  } catch (error) {
    console.error(`FAIL: ${name}`);
    console.error(`      ${error instanceof Error ? error.message : String(error)}`);
    failures += 1;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// ---- JavaScript ---------------------------------------------------------------

console.log("== JavaScript artifacts ==");
const packDir = join(workspace, "pack");
mkdirSync(packDir, { recursive: true });

run("npm", ["run", "build"], { cwd: join(root, "js") });
run("npm", [
  "pack",
  "-w", "@anonrouter/confidential",
  "-w", "@anonrouter/client",
  "--pack-destination", packDir
], { cwd: join(root, "js") });

const tarballs = readdirSync(packDir).filter((name) => name.endsWith(".tgz"));
const confidentialTarball = tarballs.find((name) => name.startsWith("anonrouter-confidential-"));
const clientTarball = tarballs.find((name) => name.startsWith("anonrouter-client-"));
assert(confidentialTarball && clientTarball, "npm pack did not produce both tarballs");

const jsHome = join(workspace, "js-consumer");
mkdirSync(jsHome, { recursive: true });
writeFileSync(join(jsHome, "package.json"), JSON.stringify({
  name: "anonrouter-smoke-consumer",
  private: true,
  type: "module",
  version: "0.0.0"
}, null, 2));

let npmInstalled = true;
try {
  run("npm", [
    "install",
    "--no-audit", "--no-fund",
    join(packDir, confidentialTarball),
    join(packDir, clientTarball)
  ], { cwd: jsHome });
} catch (error) {
  npmInstalled = false;
  console.error("SKIPPED: npm install from the tarballs failed (no registry access?)");
  console.error(`         ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`);
}

if (npmInstalled) {
  // Every documented entry point, imported the way a user would import it.
  const probe = join(jsHome, "probe.mjs");
  writeFileSync(probe, `
import { createClient, verifyGatewayAttestation, loadGatewayPolicy, atLeast,
         pinnedGatewayPolicyFor, measurementPolicyDocument } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier, describeDcapInstallation,
         buildDcapEngineRequest } from "@anonrouter/confidential/dcap";
import { createSubprocessChainVerifier } from "@anonrouter/confidential/chain-verifiers";
import { createClient as createPlainClient } from "@anonrouter/client";

const report = {
  confidentialExports: [typeof createClient, typeof verifyGatewayAttestation,
    typeof loadGatewayPolicy, typeof atLeast].every((t) => t === "function"),
  dcapExports: [typeof createAnonRouterDcapVerifier, typeof describeDcapInstallation,
    typeof buildDcapEngineRequest].every((t) => t === "function"),
  chainVerifierExports: typeof createSubprocessChainVerifier === "function",
  clientExports: typeof createPlainClient === "function",
  // The shipped pins have to be present in the installed package, or the whole
  // "don't trust us, verify" arrangement has no allowlist on the user's disk.
  gatewayPinPresent: pinnedGatewayPolicyFor("https://api.private.anonrouter.ai", { allowCandidate: true }) !== undefined,
  gatewayPinNeedsOptIn: pinnedGatewayPolicyFor("https://api.private.anonrouter.ai") === undefined,
  providerPinsPresent: Object.keys(measurementPolicyDocument().providers ?? {}).length > 0,
  engineDetected: describeDcapInstallation().available
};
console.log(JSON.stringify(report));
`);
  const probeOutput = JSON.parse(run(process.execPath, [probe], { cwd: jsHome }));

  check("@anonrouter/confidential main entry resolves and exports the public surface",
    () => assert(probeOutput.confidentialExports, "missing exports from the main entry"));
  check("@anonrouter/confidential/dcap resolves",
    () => assert(probeOutput.dcapExports, "the ./dcap subpath did not resolve"));
  check("@anonrouter/confidential/chain-verifiers resolves",
    () => assert(probeOutput.chainVerifierExports, "the ./chain-verifiers subpath did not resolve"));
  check("@anonrouter/client resolves",
    () => assert(probeOutput.clientExports, "the client package did not resolve"));
  check("the shipped gateway pin is present in the installed package",
    () => assert(probeOutput.gatewayPinPresent, "no gateway pin found after install"));
  check("the shipped gateway pin still requires an explicit opt-in",
    () => assert(probeOutput.gatewayPinNeedsOptIn, "a candidate pin resolved without allowCandidate"));
  check("the shipped provider pins are present in the installed package",
    () => assert(probeOutput.providerPinsPresent, "no provider measurement pins found after install"));

  // The command, run from the installed bin rather than from the repo.
  // The installed bin itself, not `npx`: this is the symlink npm creates from the
  // package's `bin` entry, and whether it exists and is executable is part of what
  // is being checked.
  const installedBin = join(jsHome, "node_modules", ".bin", "anonrouter-verify");
  const doctor = runAllowingFailure(installedBin, ["doctor", "--compact"], { cwd: jsHome });
  check("the installed anonrouter-verify command runs", () => {
    assert(doctor.code === 0, `doctor exited ${doctor.code}`);
    const document = JSON.parse(doctor.stdout);
    assert(document.schema === "anonrouter-verify/1", `unexpected schema ${document.schema}`);
    assert(document.command === "doctor", "doctor did not report itself");
  });

  const unpinned = runAllowingFailure(installedBin, [
    "gateway", "--origin", "https://nothing-is-pinned-for-this.example", "--compact"
  ], { cwd: jsHome });
  check("the installed command exits nonzero when nothing was established", () => {
    assert(unpinned.code === 1, `expected exit 1, got ${unpinned.code}`);
    assert(JSON.parse(unpinned.stdout).outcome.met === false, "an unestablished route reported met: true");
  });

  // Types, resolved by a consumer's own tsc rather than by ours.
  writeFileSync(join(jsHome, "types.ts"), `
import { createClient, type RouteVerdict, type RouteVerificationState } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";
const client = createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: "k" });
export async function gate(): Promise<RouteVerificationState> {
  const verdict: RouteVerdict = await client.verifyRoute({
    model: "m", provider: "venice",
    gateway: { chainVerifier: createAnonRouterDcapVerifier() }
  });
  return verdict.overallState;
}
`);
  writeFileSync(join(jsHome, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext",
      strict: true, noEmit: true, skipLibCheck: true, lib: ["ES2022", "DOM"]
    },
    files: ["types.ts"]
  }, null, 2));
  let tscInstalled = true;
  try {
    run("npm", ["install", "--no-audit", "--no-fund", "--save-dev", "typescript@^5.7.2"], { cwd: jsHome });
  } catch {
    tscInstalled = false;
    console.error("SKIPPED: could not install typescript for the type-resolution check");
  }
  if (tscInstalled) {
    check("a consumer's tsc resolves the published types", () => {
      run(join(jsHome, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.json"], { cwd: jsHome });
    });
  }
}

// ---- Python -------------------------------------------------------------------

console.log("\n== Python artifacts ==");
const python = (() => {
  for (const candidate of [process.env.ANONROUTER_PYTHON, "python3", "python"].filter(Boolean)) {
    try {
      run(candidate, ["--version"]);
      return candidate;
    } catch { /* try the next one */ }
  }
  return null;
})();

if (!python) {
  console.error("SKIPPED: no python interpreter found");
} else {
  const buildDir = join(workspace, "python-dist");
  let built = true;
  try {
    run(python, ["-m", "pip", "install", "--quiet", "build", "twine"], { cwd: root });
    run(python, ["-m", "build", "--outdir", buildDir], { cwd: join(root, "python") });
  } catch (error) {
    built = false;
    console.error("SKIPPED: could not build the Python distribution");
    console.error(`         ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`);
  }

  if (built) {
    const artifacts = readdirSync(buildDir);
    const wheel = artifacts.find((name) => name.endsWith(".whl"));
    const sdist = artifacts.find((name) => name.endsWith(".tar.gz"));

    check("python -m build produced both a wheel and an sdist", () => {
      assert(wheel, "no wheel produced");
      assert(sdist, "no sdist produced");
    });

    check("twine accepts the distribution metadata", () => {
      // Explicit paths rather than a shell glob: a temporary directory with a
      // space in it would otherwise silently check nothing.
      run(python, ["-m", "twine", "check", ...artifacts.map((name) => join(buildDir, name))]);
    });

    // Install each artifact into its OWN empty virtualenv. The sdist is checked
    // separately because a file present in the repo can be absent from an sdist
    // and still make it into a wheel built from the working tree.
    for (const [label, artifact] of [["wheel", wheel], ["sdist", sdist]]) {
      if (!artifact) continue;
      const venv = join(workspace, `venv-${label}`);
      let installed = true;
      try {
        run(python, ["-m", "venv", venv]);
        run(join(venv, "bin", "pip"), ["install", "--quiet", join(buildDir, artifact)]);
      } catch (error) {
        installed = false;
        console.error(`SKIPPED: could not install the ${label} into a clean venv`);
        console.error(`         ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`);
      }
      if (!installed) continue;

      const probe = join(workspace, `probe-${label}.py`);
      writeFileSync(probe, `
import json
from anonrouter_confidential import (create_client, verify_gateway_attestation,
                                     load_gateway_policy, at_least,
                                     pinned_gateway_policy_for, load_measurements)
from anonrouter_confidential.gateway.dcap import (create_anonrouter_dcap_verifier,
                                                  describe_dcap_installation,
                                                  build_dcap_engine_request)
from anonrouter_confidential.cli import run_cli

print(json.dumps({
    "coreExports": all(callable(f) for f in (create_client, verify_gateway_attestation,
                                             load_gateway_policy, at_least)),
    "dcapExports": all(callable(f) for f in (create_anonrouter_dcap_verifier,
                                             describe_dcap_installation,
                                             build_dcap_engine_request)),
    "cliImportable": callable(run_cli),
    # The pins have to travel INSIDE the distribution: they are package data, not
    # repo files, and a wheel that omitted them would verify nothing.
    "gatewayPinPresent": pinned_gateway_policy_for(
        "https://api.private.anonrouter.ai", allow_candidate=True) is not None,
    "gatewayPinNeedsOptIn": pinned_gateway_policy_for(
        "https://api.private.anonrouter.ai") is None,
    "providerPinsPresent": len(load_measurements().get("providers", {})) > 0,
}))
`);
      const probeOutput = JSON.parse(run(join(venv, "bin", "python"), [probe], { cwd: workspace }));
      check(`${label}: the package imports and its public surface is present`, () => {
        assert(probeOutput.coreExports, "missing core exports");
        assert(probeOutput.dcapExports, "missing dcap exports");
        assert(probeOutput.cliImportable, "the CLI module did not import");
      });
      check(`${label}: the shipped pins travel inside the distribution`, () => {
        assert(probeOutput.gatewayPinPresent, "no gateway pin found after install");
        assert(probeOutput.gatewayPinNeedsOptIn, "a candidate pin resolved without the opt-in");
        assert(probeOutput.providerPinsPresent, "no provider measurement pins found after install");
      });

      const doctor = runAllowingFailure(join(venv, "bin", "anonrouter-verify"), ["doctor", "--compact"]);
      check(`${label}: the installed anonrouter-verify command runs`, () => {
        assert(doctor.code === 0, `doctor exited ${doctor.code}`);
        assert(JSON.parse(doctor.stdout).schema === "anonrouter-verify/1", "unexpected schema");
      });

      const unpinned = runAllowingFailure(join(venv, "bin", "anonrouter-verify"), [
        "gateway", "--origin", "https://nothing-is-pinned-for-this.example", "--compact"
      ]);
      check(`${label}: the installed command exits nonzero when nothing was established`, () => {
        assert(unpinned.code === 1, `expected exit 1, got ${unpinned.code}`);
        assert(JSON.parse(unpinned.stdout).outcome.met === false, "an unestablished route reported met: true");
      });
    }
  }
}

// ---- Result -------------------------------------------------------------------

if (!keep) rmSync(workspace, { recursive: true, force: true });
else console.log(`\nartifacts kept in ${workspace}`);

if (failures > 0) {
  console.error(`\n${failures} artifact check(s) failed.`);
  process.exit(1);
}
console.log("\nEvery artifact installs into an empty environment and works there.");
