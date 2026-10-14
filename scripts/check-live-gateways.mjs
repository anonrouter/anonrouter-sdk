#!/usr/bin/env node
// Credential-free acceptance of the exact packed JS/Python distributions.
// A live gateway may supply evidence, but never the policy this check accepts.
// Native engine bytes must match a checksum reviewed outside the gateway.
//
// REQUIRED: api.anonrouter.ai (GCP content nodes) in both languages, held to the
// owner-signed release policy v3 under the owner root packaged in this
// repository (shared/release-policy-v3-authority.json), hardware verified on
// one retained TLS socket. The only tolerated advisory gaps are the two this
// SDK reports for every current node: no Google CCEL replay, and no published
// GCE PZID (instanceIdentity "unverified").
//
// INFORMATIONAL: api.private.anonrouter.ai, the deprecated Phala rollback name.
// It is recorded but never fails the gate (pass --require-phala to make it
// fatal while Phala is still the rollback target and you want proof of it).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
function option(name, fallback) {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  if (!args[i + 1] || args[i + 1].startsWith("--")) throw new Error(`missing ${name}`);
  return args[i + 1];
}
const artifacts = resolve(option("--artifacts", "dist/artifacts"));
const binary = resolve(option("--dcap-binary", join(artifacts, "anonrouter-dcap-verifier-linux-amd64")));
const checksum = option("--dcap-sha256", null);
const output = option("--out", null);
const requirePhala = args.includes("--require-phala");
const v3Authority = JSON.parse(readFileSync(new URL("../shared/release-policy-v3-authority.json", import.meta.url), "utf8"));
const GCP_ORIGIN = "https://api.anonrouter.ai";
const PHALA_ORIGIN = "https://api.private.anonrouter.ai";
const TOLERATED_GCP_ADVISORIES = new Set(["firmware_event_log_replayed", "gce_instance_identity"]);
const python = process.env.ANONROUTER_PYTHON || "python3";
const version = JSON.parse(readFileSync(new URL("../js/confidential/package.json", import.meta.url), "utf8")).version;
const sums = new Map(readFileSync(join(artifacts, "SHA256SUMS"), "utf8").trim().split("\n")
  .map(line => { const match = /^([0-9a-f]{64})  ([^/]+)$/.exec(line); if (!match) throw new Error("malformed checksum record"); return [match[2], match[1]]; }));
function digest(file) { return createHash("sha256").update(readFileSync(file)).digest("hex"); }
const engineDigest = digest(binary);
const acceptedEngine = checksum || sums.get("anonrouter-dcap-verifier-linux-amd64");
if (!acceptedEngine || engineDigest !== acceptedEngine) throw new Error("DCAP engine checksum mismatch or absent");
const packages = [`anonrouter-confidential-${version}.tgz`, `anonrouter-client-${version}.tgz`,
  `anonrouter_confidential-${version}-py3-none-any.whl`];
for (const file of packages) if (!sums.has(file) || digest(join(artifacts, file)) !== sums.get(file)) throw new Error(`artifact checksum mismatch: ${file}`);
const workspace = mkdtempSync(join(tmpdir(), "anonrouter-live-sdk-"));
function run(command, argv, options = {}) {
  return execFileSync(command, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120000, ...options });
}
const evidence = { schema: "anonrouter-packed-sdk-live-gateway-v1", verifiedAt: new Date().toISOString(),
  version, engineSha256: engineDigest, artifacts: Object.fromEntries(packages.map(file => [file, sums.get(file)])), checks: [] };
let failed = false;
try {
  const js = join(workspace, "js"); mkdirSync(js); writeFileSync(join(js, "package.json"), '{"private":true}');
  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...packages.slice(0, 2).map(file => join(artifacts, file))], { cwd: js });
  const venv = join(workspace, "venv"); run(python, ["-m", "venv", venv]);
  // Retained-socket verification needs the reviewed HTTPX/HTTPCore pair.
  run(join(venv, "bin", "python"), ["-m", "pip", "install", "--quiet", `${join(artifacts, packages[2])}[connection-binding]`]);
  const commands = [["javascript", process.execPath, [join(js, "node_modules/@anonrouter/confidential/dist/cli.js")]],
    ["python", join(venv, "bin", "anonrouter-verify"), []]];
  for (const [language, command, prefix] of commands) for (const origin of [GCP_ORIGIN, PHALA_ORIGIN]) {
    const required = origin === GCP_ORIGIN || requirePhala;
    let document;
    let code = 0;
    try {
      document = JSON.parse(run(command, [...prefix, "gateway", "--origin", origin,
        "--dcap-binary", binary, "--dcap-sha256", engineDigest, "--require", "hardware_verified"]));
    } catch (error) {
      code = error.status ?? 2;
      try { document = JSON.parse(String(error.stdout)); } catch { /* retain only fixed failure metadata */ }
    }
    const gateway = document?.gateway;
    const common = code === 0 && gateway?.state === "hardware_verified" && gateway?.failedChecks?.length === 0
      && document?.bindingMismatches?.length === 0 && Array.isArray(gateway?.advisoryGaps);
    const passed = origin === GCP_ORIGIN
      ? common && gateway.policy?.origin === "signed-release-policy-v3"
        && gateway.policy?.ownerRootSha256 === v3Authority.trust.ownerRootSha256
        && gateway.policy?.sequence >= v3Authority.trust.minimumPolicySequence
        && gateway.tlsSpki?.source === "retained-connection" && gateway.tlsSpki?.matchesAttested === true
        && gateway.advisoryGaps.every(name => TOLERATED_GCP_ADVISORIES.has(name))
      : common && gateway.policy?.origin === "package-pinned" && gateway.advisoryGaps.length === 0;
    evidence.checks.push({ language, origin, required, passed, exitCode: code, state: gateway?.state ?? "unavailable",
      policyOrigin: gateway?.policy?.origin ?? null, policySource: gateway?.policy?.source ?? null,
      policyVersion: gateway?.policy?.version ?? null, policySequence: gateway?.policy?.sequence ?? null,
      tcbStatus: gateway?.tcbStatus ?? null, tlsSpkiSource: gateway?.tlsSpki?.source ?? null,
      failedChecks: gateway?.failedChecks ?? [], advisoryGaps: gateway?.advisoryGaps ?? [] });
    console.log(`${passed ? "PASS" : required ? "FAIL" : "INFO (not required)"} ${language} ${origin}: ${gateway?.state ?? "unavailable"}`);
    if (required) failed ||= !passed;
  }
} finally { rmSync(workspace, { recursive: true, force: true }); }
if (output) writeFileSync(output, JSON.stringify(evidence, null, 2) + "\n");
process.exitCode = failed ? 1 : 0;
