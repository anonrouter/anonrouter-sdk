#!/usr/bin/env node
// Preparation/assembly ONLY. Never reads a signing key or publishes anything.
//
//   prepare       legacy policy + one retained manifest          -> signable payload
//   prepare       phala-dstack-kms tuple policy + manifest set    -> signable payload + review
//   qualify-gcp   gcp-tdx-native pilot policy + reference boots   -> NON-SIGNABLE candidate
//   assemble / verify                                             -> production roots only
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalGatewayPolicyJson, packagedGatewayPolicyAuthority, GATEWAY_POLICY_DOMAIN,
  verifySignedGatewayPolicy, assertGatewayPolicySecurityFloor
} from "../js/confidential/dist/gateway/authority.js";
import { loadGatewayPolicy, GATEWAY_PLATFORM_QUALIFIED } from "../js/confidential/dist/gateway/policy.js";
import { gatewayBindingHash, normalizeGatewayBinding } from "../js/confidential/dist/gateway/binding.js";
import { parseTdxQuote } from "../js/confidential/dist/verify/tdx.js";
import { normalizeQuoteHex } from "../js/confidential/dist/gateway/dcap/collateral.js";
import { buildDcapEngineRequest, engineReportDisagreement, fileSha256, runDcapEngine } from "../js/confidential/dist/gateway/dcap/engine.js";
import { classifyCcel, inspectUki, parseCcel, replayCcel, sha } from "./gateway-qualification.mjs";

export function prepareGatewayPolicyRelease(manifestBytes, policyDocument, sequence, issuedAtMs, expiresAtMs) {
  const root = packagedGatewayPolicyAuthority();
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const policy = loadGatewayPolicy(policyDocument);
  assertGatewayPolicySecurityFloor(policy);
  // A tuple-form policy can name several releases, but a retained manifest names
  // one. Its correlation procedure is not reviewed yet, and gcp-tdx-native is not
  // qualified for signed approval at all, so refuse rather than half-check it.
  if (policy.platformKind !== undefined) throw new Error("tuple-form policies use prepareTupleGatewayPolicyRelease (phala) or qualify-gcp (never signable)");
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
const MANIFEST_SET_SCHEMA = "anonrouter.release-manifest-set/v1";
const ZERO_REGISTER = "0".repeat(96);

function retainedManifest(bytes) {
  let manifest;
  try { manifest = JSON.parse(Buffer.from(bytes).toString("utf8")); } catch { throw new Error("retained manifest is not JSON"); }
  if (manifest?.schema !== "anonrouter.release-manifest/v2" || manifest.status !== "live-hardware-measurement"
    || manifest.source?.dirty !== false || manifest.deployment?.transport !== "in-tee-tls"
    || typeof manifest.release_id !== "string" || typeof manifest.app_compose !== "string") {
    throw new Error("a retained finalized clean hardware/TLS manifest is required");
  }
  // The manifest's own measured compose must hash to what it says was measured.
  if (sha("sha256", Buffer.from(manifest.app_compose, "utf8")) !== manifest.compose?.measured_hash) {
    throw new Error(`manifest ${manifest.release_id} app_compose does not hash to its measured compose hash`);
  }
  return { manifest, sha256: sha("sha256", bytes) };
}

/**
 * Overlapping Phala releases as ONE signed approval. Every tuple must be backed
 * by exactly one independently retained release manifest, every manifest must
 * back at least one tuple, and the approval's manifestSha256 commits to the
 * whole set. Values release-manifest/v2 does not record (MRTD, RTMR0..2 and the
 * KMS key-provider payload) are listed as UNBOUND in the review for a human to
 * compare with retained hardware evidence before anyone signs.
 */
/** The canonical manifest-set document and the digest a tuple policy's source must name. */
export function gatewayManifestSet(manifestBytesList) {
  const manifests = manifestBytesList.map(retainedManifest);
  const set = { schema: MANIFEST_SET_SCHEMA,
    manifests: manifests.map(m => ({ releaseId: m.manifest.release_id, sha256: m.sha256 }))
      .sort((a, b) => a.sha256 < b.sha256 ? -1 : 1) };
  const json = canonicalGatewayPolicyJson(set);
  return { manifests, set, json, sha256: sha("sha256", Buffer.from(json, "utf8")) };
}

export function prepareTupleGatewayPolicyRelease(manifestBytesList, policyDocument, sequence, issuedAtMs, expiresAtMs,
  root = packagedGatewayPolicyAuthority()) {
  const policy = loadGatewayPolicy(policyDocument);
  assertGatewayPolicySecurityFloor(policy);
  if (policy.platformKind !== "phala-dstack-kms") {
    throw new Error("only phala-dstack-kms tuples are signable; gcp-tdx-native uses qualify-gcp and is never signable");
  }
  if (!GATEWAY_PLATFORM_QUALIFIED[policy.platformKind]) throw new Error("platform kind is not qualified");
  if (!Array.isArray(manifestBytesList) || manifestBytesList.length === 0 || manifestBytesList.length > policy.releaseTuples.length) {
    throw new Error("one to tuple-count retained manifests are required");
  }
  const { manifests, set, json: manifestSetJson, sha256: manifestSha256 } = gatewayManifestSet(manifestBytesList);
  if (new Set(manifests.map(m => m.sha256)).size !== manifests.length
    || new Set(manifests.map(m => m.manifest.release_id)).size !== manifests.length) throw new Error("duplicate retained manifest or release");
  if (policy.source !== `anonrouter-release-manifest-sha256:${manifestSha256}`) {
    throw new Error(`policy.source must be anonrouter-release-manifest-sha256:${manifestSha256} (the canonical manifest set)`);
  }
  if (policy.origins.some(o => !root.origins.includes(o))) throw new Error("policy names an origin outside the packaged authority");
  if (!Number.isSafeInteger(sequence) || sequence < root.minSequence
    || !Number.isSafeInteger(issuedAtMs) || !Number.isSafeInteger(expiresAtMs)
    || issuedAtMs < 0 || expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > root.maxLifetimeMs) throw new Error("invalid sequence or validity window");
  const used = new Set(), correlations = [];
  for (const tuple of policy.releaseTuples) {
    const backing = manifests.filter(m => m.manifest.release_id === tuple.releaseId);
    if (backing.length !== 1) throw new Error(`tuple ${tuple.tupleId} is not backed by exactly one retained manifest`);
    const { manifest, sha256 } = backing[0];
    const mismatched = [
      ["appId", manifest.deployment.app_id], ["composeHash", manifest.compose.measured_hash],
      ["osImageHash", manifest.deployment.os_image_hash],
      // dstack writes 0x01 || compose hash || zero padding into MRCONFIGID.
      ["mrConfigId", `01${manifest.compose.measured_hash}${"00".repeat(15)}`]
    ].filter(([field, value]) => tuple[field] !== value).map(([field]) => field);
    if (mismatched.length) throw new Error(`tuple ${tuple.tupleId} disagrees with its retained manifest: ${mismatched.join(", ")}`);
    if (!policy.origins.includes(manifest.deployment.origin)) throw new Error(`tuple ${tuple.tupleId} manifest origin is not authorized by the policy`);
    if (tuple.expiresAtMs <= issuedAtMs) throw new Error(`tuple ${tuple.tupleId} has already expired at issue time`);
    used.add(sha256);
    correlations.push({ tupleId: tuple.tupleId, releaseId: tuple.releaseId, manifestSha256: sha256,
      boundToManifest: { appId: tuple.appId, composeHash: tuple.composeHash, osImageHash: tuple.osImageHash, mrConfigId: tuple.mrConfigId },
      unboundReviewRequired: { mrTd: tuple.mrTd, rtmr0: tuple.rtmr0, rtmr1: tuple.rtmr1, rtmr2: tuple.rtmr2,
        keyProviderPayload: tuple.keyProviderPayload },
      validity: { notBeforeMs: tuple.notBeforeMs, expiresAtMs: tuple.expiresAtMs } });
  }
  if (used.size !== manifests.length) throw new Error("every retained manifest must back at least one tuple");
  const payload = canonicalGatewayPolicyJson({ schema: "anonrouter.gateway-policy/v1", authority: root.authority,
    sequence, issuedAtMs, expiresAtMs, manifestSha256, policy: policyDocument });
  const review = {
    schema: "anonrouter.gateway-policy-tuple-review/v1",
    payloadSha256: sha("sha256", Buffer.from(payload, "utf8")),
    manifestSet: set,
    tuples: correlations,
    reviewerMustConfirm: [
      "Every unboundReviewRequired register equals a retained, natively DCAP-verified quote for that release; release-manifest/v2 does not record them.",
      "Every keyProviderPayload names the production KMS identity for its release.",
      "The overlap is intended: each tuple's validity window ends when its release is retired."
    ]
  };
  return { payload, signingBytes: GATEWAY_POLICY_DOMAIN + payload, manifestSetJson, review };
}

const CANDIDATE_SCHEMA = "anonrouter.gateway-policy-qualification-candidate/v1";

function readArtifact(base, path, label) {
  if (typeof path !== "string" || path.length === 0) throw new Error(`reference ${label} path is required`);
  return readFileSync(resolve(base, path));
}

async function nativeDcap(quoteHex, collateralBytes, options) {
  if (!options.dcapBinary) return { passed: false, detail: "not run: pass --dcap-binary with retained collateral; a verdict file is not accepted" };
  let collateral;
  try { const parsed = JSON.parse(collateralBytes.toString("utf8")); collateral = parsed.collateral ?? parsed; }
  catch { return { passed: false, detail: "collateral is not JSON" }; }
  const verdict = await runDcapEngine(options.dcapBinary,
    buildDcapEngineRequest(quoteHex, collateral, Math.floor(options.nowMs / 1000), ["UpToDate"]), 30_000);
  const disagreement = engineReportDisagreement(quoteHex, verdict.report);
  const passed = verdict.verified === true && verdict.tcbStatus === "UpToDate" && verdict.advisoryIds.length === 0
    && verdict.report !== null && disagreement === null;
  return { passed, detail: passed ? `engine=${verdict.engine} tcb=UpToDate`
    : disagreement ?? verdict.error ?? `tcb=${verdict.tcbStatus} advisories=${verdict.advisoryIds.join(",") || "none"}`,
    engine: verdict.engine };
}

/** Re-check one reference boot against its tuple. Every check is recomputed here. */
async function qualifyReference(policy, tuple, reference, base, options) {
  const checks = [];
  const add = (name, passed, detail) => { checks.push({ name, passed: passed === true, ...(detail ? { detail } : {}) }); return passed === true; };
  const gatewayBytes = readArtifact(base, reference.gatewayEvidence, "gatewayEvidence");
  const ccelBytes = readArtifact(base, reference.ccel, "ccel");
  const ukiBytes = readArtifact(base, reference.uki, "uki");
  const composeBytes = readArtifact(base, reference.compose, "compose");
  const collateralBytes = readArtifact(base, reference.collateral, "collateral");
  const digests = { gatewayEvidenceSha256: sha("sha256", gatewayBytes), ccelSha256: sha("sha256", ccelBytes),
    ukiFileSha256: sha("sha256", ukiBytes), composeSha256: sha("sha256", composeBytes),
    collateralSha256: sha("sha256", collateralBytes) };

  // The reference boot's own gateway_attest output: binding plus quote.
  let evidence, binding = null, quoteHex = null, quote = null;
  try { evidence = JSON.parse(gatewayBytes.toString("utf8")); } catch { evidence = null; }
  try { binding = normalizeGatewayBinding(evidence?.binding); } catch { binding = null; }
  quoteHex = normalizeQuoteHex(evidence?.quote);
  quote = quoteHex ? parseTdxQuote(quoteHex) : null;
  if (quoteHex) digests.quoteSha256 = sha("sha256", Buffer.from(quoteHex, "hex"));
  add("quote_parsed", quote !== null && quote.teeType === 0x81);
  add("quote_not_debug", quote !== null && !quote.debugEnabled);
  add("report_data_binds_binding", binding !== null && quote !== null && gatewayBindingHash(binding) === quote.reportData.toLowerCase());
  add("binding_correlates_with_tuple", binding !== null && binding.release_id === tuple.releaseId && binding.app_id === tuple.appId
    && binding.compose_hash === tuple.composeHash && binding.transport === "in-tee-tls" && policy.origins.includes(binding.origin));
  add("instance_id_derives_from_boot_key", binding !== null && binding.key_alg === "ed25519" && /^[0-9a-f]{64}$/.test(binding.public_key)
    && sha("sha256", Buffer.from(binding.public_key, "hex")) === binding.instance_id);
  add("quote_registers_match_tuple", quote !== null && quote.mrTd === tuple.mrTd && quote.rtmr0 === tuple.rtmr0
    && quote.rtmr1 === tuple.rtmr1 && quote.rtmr2 === tuple.rtmr2 && quote.tdAttributes === tuple.tdAttributes);
  add("rtmr3_unextended", quote !== null && quote.rtmr3 === ZERO_REGISTER);
  add("owner_config_registers_zero", quote !== null && [quote.mrConfigId, quote.mrOwner, quote.mrOwnerConfig].every(v => v === ZERO_REGISTER));
  const dcap = quoteHex ? await nativeDcap(quoteHex, collateralBytes, options) : { passed: false, detail: "no quote" };
  add("native_dcap_verified", dcap.passed, dcap.detail);

  let uki = null;
  try { uki = inspectUki(ukiBytes); digests.ukiAuthenticodeSha384 = uki.authenticodeSha384; }
  catch (error) { add("uki_parsed", false, error.message); }
  if (uki) {
    add("uki_parsed", true);
    add("uki_cmdline_names_verity_root", uki.rootfsHash === tuple.appId, `dstack.rootfs_hash=${uki.rootfsHash}`);
    add("uki_cmdline_hardened", uki.cmdlineFindings.length === 0, uki.cmdlineFindings.join("; ") || undefined);
  }
  try {
    const log = parseCcel(ccelBytes);
    const replayed = replayCcel(log);
    add("ccel_replays_quote", quote !== null && replayed[0] === quote.rtmr0 && replayed[1] === quote.rtmr1
      && replayed[2] === quote.rtmr2 && replayed[3] === quote.rtmr3);
    const allowed = Array.isArray(reference.allowedCodeDigests) ? reference.allowedCodeDigests : [];
    const classified = classifyCcel(log, uki?.authenticodeSha384 ?? null, allowed);
    // Hardware gate N1: firmware measured exactly this UKI, and nothing else, as RTMR1's boot application.
    add("rtmr1_boot_application_is_uki", uki !== null && classified.rtmr1BootApplications.length === 1
      && classified.rtmr1BootApplications[0] === uki.authenticodeSha384);
    add("ccel_events_classified", classified.findings.length === 0 && classified.unlistedCode.length === 0,
      [...classified.findings, ...classified.unlistedCode].join("; ") || undefined);
  } catch (error) {
    add("ccel_replays_quote", false, error.message);
    add("rtmr1_boot_application_is_uki", false, error.message);
    add("ccel_events_classified", false, error.message);
  }
  add("compose_digest_matches_tuple", digests.composeSha256 === tuple.composeHash);

  // Optional independent cross-check: the guest's native ar-guest-verify output
  // for the same artifacts. Only its DIGESTS are compared; its booleans are not read.
  if (reference.nativeReference) {
    let native = null;
    try { native = JSON.parse(readArtifact(base, reference.nativeReference, "nativeReference").toString("utf8")); } catch { native = null; }
    const pin = native?.proposed_pin;
    add("native_reference_digests_agree", native !== null && uki !== null && quote !== null
      && native.quote_sha256 === digests.quoteSha256 && native.uki_authenticode_sha384_edk2 === uki.authenticodeSha384
      && pin?.mrtd === quote.mrTd && pin?.rtmr0 === quote.rtmr0 && pin?.rtmr1 === quote.rtmr1 && pin?.rtmr2 === quote.rtmr2
      && pin?.rtmr3 === quote.rtmr3 && pin?.reference_quote_sha256 === digests.quoteSha256);
  } else add("native_reference_digests_agree", false, "not supplied");
  // P2 and P4 are judged separately; every other check is recomputed here from bytes.
  const local = checks.filter(c => !["native_dcap_verified", "native_reference_digests_agree"].includes(c.name));
  return { tupleId: tuple.tupleId, shape: typeof reference.shape === "string" ? reference.shape : null, digests, checks,
    localChecksPassed: local.every(c => c.passed), allChecksPassed: checks.every(c => c.passed) };
}

/**
 * A NON-SIGNABLE qualification candidate for an explicit gcp-tdx-native pilot.
 * It carries no signing bytes and no gateway-policy payload, its schema is not
 * one the feed reads, and the SDK refuses the platform kind regardless. It is the
 * reviewable record of exactly which artifact digests a future qualification
 * would stand on and which promotion gates are still open.
 */
export async function qualifyGcpPolicyCandidate(policyDocument, evidenceBundle, options) {
  if (options?.unqualifiedPlatformPilot !== true) throw new Error("qualify-gcp requires an explicit unqualified-platform pilot acknowledgement");
  if (!Number.isSafeInteger(options.nowMs) || options.nowMs <= 0) throw new Error("nowMs is required");
  const policy = loadGatewayPolicy(policyDocument);
  assertGatewayPolicySecurityFloor(policy);
  if (policy.platformKind !== "gcp-tdx-native") throw new Error("qualify-gcp accepts only gcp-tdx-native policies");
  if (evidenceBundle?.schema !== "anonrouter.gcp-qualification-evidence/v1" || !Array.isArray(evidenceBundle.references)) {
    throw new Error("evidence bundle schema anonrouter.gcp-qualification-evidence/v1 is required");
  }
  const base = options.baseDir ?? process.cwd();
  const references = [];
  for (const reference of evidenceBundle.references) {
    const tuple = policy.releaseTuples.find(t => t.tupleId === reference?.tupleId);
    if (!tuple) throw new Error(`reference names unknown tuple ${String(reference?.tupleId)}`);
    references.push(await qualifyReference(policy, tuple, reference, base, options));
  }
  const covered = new Set(references.filter(r => r.localChecksPassed).map(r => r.tupleId));
  const uncovered = policy.releaseTuples.map(t => t.tupleId).filter(id => !covered.has(id));
  const all = name => references.length > 0 && references.every(r => r.checks.find(c => c.name === name)?.passed);
  const status = ok => ok ? "satisfied" : "unmet";
  const gate = [
    { id: "P1-reference-boot-per-tuple", status: status(uncovered.length === 0),
      requirement: "Every tuple has a reference boot whose quote, CCEL, UKI, gateway binding and compose were re-checked here.",
      evidence: uncovered.length ? `tuples without a passing reference: ${uncovered.join(", ")}` : "all tuples covered" },
    { id: "P2-native-dcap", status: status(all("native_dcap_verified")),
      requirement: "This tool ran the reviewed native DCAP engine on each reference quote with retained Intel-signed collateral: verified, UpToDate, no advisories, engine and SDK agree on the TD report." },
    { id: "P3-gate-n1-uki-in-rtmr1", status: status(all("native_dcap_verified") && all("rtmr1_boot_application_is_uki") && all("ccel_replays_quote")),
      requirement: "Hardware gate N1, derived (never asserted): on a DCAP-verified quote, the replayed CCEL shows exactly one RTMR1 boot application equal to the UKI's EDK2 Authenticode SHA-384." },
    { id: "P4-independent-native-cross-check", status: status(all("native_reference_digests_agree")),
      requirement: "ar-guest-verify reference over the same artifacts proposes identical quote, UKI Authenticode and register digests." },
    { id: "P5-rootfs-and-application-content", status: "external",
      requirement: "ar-guest-verify release-check accepts the exact UKI, rootfs, app manifest, compose and image layout; the verity root it recomputes equals each tuple appId.",
      evidence: references.map(r => `${r.tupleId}: verity=${policy.releaseTuples.find(t => t.tupleId === r.tupleId).appId} compose=${r.digests.composeSha256}`).join("; ") },
    { id: "P6-firmware-endorsement", status: "external",
      requirement: "A Google-signed launch endorsement (gce-tcb-verifier) for every tuple MRTD, retained beside the candidate.",
      evidence: [...new Set(policy.releaseTuples.map(t => t.mrTd))].join(", ") },
    { id: "P7-reproducible-uki", status: "external",
      requirement: "An independent rebuild of each release UKI reproduces the same EDK2 Authenticode SHA-384.",
      evidence: references.map(r => `${r.tupleId}: ${r.digests.ukiAuthenticodeSha384 ?? "unparsed"}`).join("; ") },
    { id: "P8-sdk-qualification-release", status: GATEWAY_PLATFORM_QUALIFIED["gcp-tdx-native"] ? "satisfied" : "unmet",
      requirement: "A separately reviewed SDK release sets GATEWAY_PLATFORM_QUALIFIED[gcp-tdx-native] = true and defines tuple-form signed approval for this kind." }
  ];
  return {
    schema: CANDIDATE_SCHEMA,
    signable: false,
    notice: "QUALIFICATION CANDIDATE ONLY. Not a gateway-policy payload, carries no signing bytes, and is refused by the packaged registry, the signed feed and every client until gcp-tdx-native is qualified.",
    platformKind: policy.platformKind,
    platformQualified: GATEWAY_PLATFORM_QUALIFIED["gcp-tdx-native"],
    checkedAtMs: options.nowMs,
    dcapBinarySha256: options.dcapBinary ? fileSha256(options.dcapBinary) : null,
    policySha256: sha("sha256", Buffer.from(canonicalGatewayPolicyJson(policyDocument), "utf8")),
    policy: policyDocument,
    references,
    promotionGate: gate,
    promotable: gate.every(g => g.status === "satisfied")
  };
}

export function assembleGatewayPolicyRelease(payload, signatures, nowMs = Date.now()) {
  const root = packagedGatewayPolicyAuthority();
  const envelope = { schema: "anonrouter.gateway-policy-envelope/v1", payload, signatures };
  // All intended origins must pass, not merely the canonical hostname.
  for (const origin of root.origins) verifySignedGatewayPolicy(envelope, root, origin, nowMs);
  return envelope;
}
async function main(args) {
  const command = args.shift(); const options = new Map();
  if (args.length % 2) throw new Error("options require values");
  for (let i=0;i<args.length;i+=2) {
    if (!args[i].startsWith("--") || options.has(args[i])) throw new Error("unknown/duplicate option");
    options.set(args[i], args[i+1]);
  }
  const required = name => { if (!options.has(name)) throw new Error(`${name} is required`); return options.get(name); };
  const allowed = command === "prepare"
    ? ["--manifest","--manifests","--policy","--sequence","--issued-at-ms","--expires-at-ms","--out"]
    : command === "qualify-gcp" ? ["--policy","--evidence","--unqualified-platform-pilot","--dcap-binary","--now-ms","--out"]
    : command === "assemble" ? ["--payload","--signatures","--out"] : ["--envelope"];
  if ([...options.keys()].some(k=>!allowed.includes(k))) throw new Error("unknown option");
  if (command === "prepare") {
    if (options.has("--manifest") === options.has("--manifests")) throw new Error("exactly one of --manifest or --manifests is required");
    const document = JSON.parse(readFileSync(required("--policy"),"utf8"));
    const window = [Number(required("--sequence")), Number(required("--issued-at-ms")), Number(required("--expires-at-ms"))];
    const path = required("--out");
    const result = options.has("--manifest")
      ? prepareGatewayPolicyRelease(readFileSync(required("--manifest")), document, ...window)
      : prepareTupleGatewayPolicyRelease(required("--manifests").split(",").map(p => readFileSync(p)), document, ...window);
    writeFileSync(path, result.payload, {flag:"wx",mode:0o644});
    writeFileSync(path+".signing-bytes",result.signingBytes,{flag:"wx",mode:0o644});
    if (result.review) {
      writeFileSync(path+".manifest-set.json", result.manifestSetJson+"\n", {flag:"wx",mode:0o644});
      writeFileSync(path+".review.json", JSON.stringify(result.review,null,2)+"\n", {flag:"wx",mode:0o644});
    }
    process.stdout.write("Prepared unsigned policy and purpose-specific signing bytes. No signature or publication performed.\n");
  } else if (command === "qualify-gcp") {
    if (required("--unqualified-platform-pilot") !== "acknowledged") throw new Error("--unqualified-platform-pilot acknowledged is required");
    const evidencePath = resolve(required("--evidence"));
    const candidate = await qualifyGcpPolicyCandidate(JSON.parse(readFileSync(required("--policy"),"utf8")),
      JSON.parse(readFileSync(evidencePath,"utf8")), { unqualifiedPlatformPilot: true, baseDir: dirname(evidencePath),
        nowMs: options.has("--now-ms") ? Number(options.get("--now-ms")) : Date.now(),
        ...(options.has("--dcap-binary") ? { dcapBinary: resolve(options.get("--dcap-binary")) } : {}) });
    writeFileSync(required("--out"), JSON.stringify(candidate,null,2)+"\n", {flag:"wx",mode:0o644});
    process.stdout.write(`Wrote NON-SIGNABLE gcp-tdx-native qualification candidate; promotable=${candidate.promotable}. Nothing signed or published.\n`);
  } else if (command === "assemble") {
    const envelope = assembleGatewayPolicyRelease(readFileSync(required("--payload"),"utf8"),JSON.parse(readFileSync(required("--signatures"),"utf8")));
    writeFileSync(required("--out"),JSON.stringify(envelope)+"\n",{flag:"wx",mode:0o644});
    process.stdout.write("Assembled policy; both production origins verified against packaged custodian roots. Not published.\n");
  } else if (command === "verify") {
    const root=packagedGatewayPolicyAuthority(); const envelope=JSON.parse(readFileSync(required("--envelope"),"utf8"));
    for(const origin of root.origins) verifySignedGatewayPolicy(envelope,root,origin,Date.now());
    process.stdout.write("Verified signed gateway policy for both production origins.\n");
  } else throw new Error("usage: gateway-policy-release.mjs prepare|qualify-gcp|assemble|verify (see docs/gateway-policy-updates.md)");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(() => { process.stderr.write("Gateway-policy release refused; check arguments, retained artifacts and required signatures.\n"); process.exitCode=1; });
}
