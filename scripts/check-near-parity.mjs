#!/usr/bin/env node
// Match the full normalized verdict fields and required check outcomes for both
// languages against the same retained public NEAR evidence and substitutions.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { verifyRawEvidence } from "../js/confidential/dist/verify/index.js";
const fixture = JSON.parse(readFileSync(new URL("../shared/vectors/near-authority.json", import.meta.url), "utf8"));
const cases = ["valid", "wrong_nonce", "wrong_model", "wrong_key", "missing_gpu", "missing_collateral", "wrong_chain", "stale_publication"];
const records = cases.map(name => {
  const evidence = structuredClone(fixture.evidence);
  let nonce = fixture.nonce, model = fixture.upstreamModel;
  if (name === "wrong_nonce") nonce = "00".repeat(32);
  if (name === "wrong_model") model = "unknown/model";
  if (name === "wrong_key") evidence.signing_public_key = "11".repeat(32);
  if (name === "missing_gpu") delete evidence.nvidia_payload;
  if (name === "missing_collateral") delete evidence.anonrouter_release_collateral;
  if (name === "wrong_chain") evidence.anonrouter_release_collateral.onchain[0].chainId = 1;
  if (name === "stale_publication") evidence.anonrouter_release_collateral.github[0].fetchedAtMs = 0;
  return { name, evidence, nonce, model, now: fixture.now };
});
const source = `import sys,json
from dataclasses import asdict
from anonrouter_confidential.client import ConfidentialClient
from anonrouter_confidential.verify.registry import verify_raw_evidence
records=json.load(sys.stdin);client=ConfidentialClient(api_key="synthetic")
results=[]
for r in records:
 e=client._expectations("other",r["model"],r["nonce"],"e2ee");e.now_ms=r["now"]
 results.append(asdict(verify_raw_evidence("other",r["evidence"],e)))
print(json.dumps(results))
`;
const py = JSON.parse(execFileSync(process.env.ANONROUTER_PYTHON || "python3", ["-c", source], { encoding: "utf8", input: JSON.stringify(records) }));
function normalized(verdict) {
  const { checks, ...fields } = verdict;
  return { ...fields, verified_at: new Date(fields.verified_at).toISOString(), expires_at: new Date(fields.expires_at).toISOString(), checks: checks.map(({ name, passed, required }) => ({ name, passed, required })) };
}
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + stable(value[k])).join(",")}}`;
  return JSON.stringify(value);
}
for (const [i, r] of records.entries()) {
  const js = verifyRawEvidence("other", r.evidence, { upstreamModel: r.model, nonce: r.nonce, privacyModality: "e2ee", now: r.now });
  if (stable(normalized(js)) !== stable(normalized(py[i]))) throw new Error(`cross-language verdict drift: ${r.name}`);
  if ((js.status === "ok") !== (r.name === "valid")) throw new Error(`unexpected trust outcome: ${r.name}`);
  console.log(`PASS ${r.name}: matching verdict and check outcomes`);
}
