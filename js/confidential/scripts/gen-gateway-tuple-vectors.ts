// Generate shared/vectors/gateway-release-tuples.json.
//
// Tuple-form gateway policies (explicit platformKind, whole release tuples
// evaluated as OR) are new security decisions, so both languages must reach the
// same verdict over the same bytes. This file pins three things:
//
//   loadCases    which policy documents parse, and which are refused
//   verifyCases  complete synthetic evidence documents and the exact verdict
//   signedCases  which signed approvals the feed accepts for a platform kind
//
//   npx tsx scripts/gen-gateway-tuple-vectors.ts
//
// EVERYTHING HERE IS SYNTHETIC. The registers, key-provider payload, signing
// keys and evidence are invented test inputs, never Google firmware values or
// production pins, and no quote here carries an Intel signature.

import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, utf8Encode } from "../src/bytes.js";
import { canonicalGatewayPolicyJson, GATEWAY_POLICY_DOMAIN, verifySignedGatewayPolicy, type GatewayPolicyAuthority } from "../src/gateway/authority.js";
import { gatewayBindingHash } from "../src/gateway/binding.js";
import { loadGatewayPolicy } from "../src/gateway/policy.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "../src/bytes.js";
import {
  buildAppCompose,
  buildSyntheticEventLog,
  buildSyntheticGcpQuote,
  buildSyntheticTdxQuote,
  buildVmConfig,
  SYNTHETIC_GCP_BOOT_KEY,
  SYNTHETIC_GCP_INSTANCE_ID,
  SYNTHETIC_GCP_REGISTERS,
  SYNTHETIC_GCP_VERITY_ROOT,
  SYNTHETIC_MR_CONFIG_ID,
  SYNTHETIC_OS_IMAGE_HASH
} from "../test/helpers/gateway-fixtures.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, "..", "..", "..", "shared", "vectors", "gateway-release-tuples.json");

const NONCE = "7".repeat(64);
const ORIGIN = "https://content.gcp.example";
const APP_ID = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98";
const SPKI = "cc".repeat(32);
const OTHER_NODE_SPKI = "dd".repeat(32);
const NOW = 1_791_327_000_000;
const DAY = 86_400_000;
const KMS_PAYLOAD = bytesToHex(utf8Encode(JSON.stringify({ name: "kms", id: "aa".repeat(33) })));
const NONE_PAYLOAD = bytesToHex(utf8Encode(JSON.stringify({ name: "none", id: "" })));

// On GCP the compose is baked into the verity root (the app id); only its hash
// travels in the binding. Release B is a different verity root and compose.
const composeA = buildAppCompose({ name: "anonrouter-content-a" });
const composeB = buildAppCompose({ name: "anonrouter-content-b" });
const ROOT_A = SYNTHETIC_GCP_VERITY_ROOT;
const ROOT_B = "6b".repeat(32);

// Two complete approved releases on two firmware/shape tuples.
const FW1 = SYNTHETIC_GCP_REGISTERS;
const FW2 = { ...SYNTHETIC_GCP_REGISTERS, mrTd: "5e".repeat(48), rtmr0: "6f".repeat(48) };

function gcpTuple(id: string, release: string, root: string, compose: { hash: string }, fw: typeof FW1, window = { notBeforeMs: NOW - DAY, expiresAtMs: NOW + DAY }) {
  return {
    tupleId: id, releaseId: release, appId: root, composeHash: compose.hash,
    mrTd: fw.mrTd, rtmr0: fw.rtmr0, rtmr1: fw.rtmr1, rtmr2: fw.rtmr2, tdAttributes: fw.tdAttributes, xfam: fw.xfam, ...window
  };
}

const floor = {
  requireInTeeTls: true, requirePrivateLogs: true, requireDigestPinnedImages: true, requireHardwareVerified: true,
  acceptableTcbStatuses: ["UpToDate"], requireEvidenceExpiry: true, maxEvidenceAgeMs: 300_000
};

const gcpPolicy = {
  platformKind: "gcp-tdx-native", source: "synthetic-gcp-tuple-vectors", version: "1", origins: [ORIGIN],
  releaseTuples: [gcpTuple("release-a@fw1", "content@a", ROOT_A, composeA, FW1), gcpTuple("release-b@fw2", "content@b", ROOT_B, composeB, FW2)],
  ...floor
};

interface GcpEvidenceOptions {
  release: string; root: string; compose: { hash: string }; fw: typeof FW1; spki?: string;
  quote?: Record<string, string>; binding?: Record<string, unknown>;
}
function gcpEvidence(options: GcpEvidenceOptions) {
  const binding = { v: 1, nonce: NONCE, app_id: options.root, instance_id: SYNTHETIC_GCP_INSTANCE_ID,
    compose_hash: options.compose.hash, release_id: options.release, origin: ORIGIN, key_alg: "ed25519",
    public_key: SYNTHETIC_GCP_BOOT_KEY, transport: "in-tee-tls", tls_spki_sha256: options.spki ?? SPKI, ...options.binding };
  return {
    binding,
    quote: buildSyntheticGcpQuote(gatewayBindingHash(binding as never), { ...options.fw, ...options.quote }),
    issued_at_ms: NOW - 1_000
  };
}

const releaseA = { release: "content@a", root: ROOT_A, compose: composeA, fw: FW1 };
const releaseB = { release: "content@b", root: ROOT_B, compose: composeB, fw: FW2 };
const otherBootKey = "e8".repeat(32);

// A Phala tuple-form policy and matching dstack evidence, for the positive
// control that tuple form also serves the existing platform.
const phalaCompose = buildAppCompose();
const phalaLog = buildSyntheticEventLog({ appId: APP_ID, composeHash: phalaCompose.hash, instanceId: INSTANCE_ID, keyProviderId: "aa".repeat(33) });
const PHALA_ORIGIN = "https://api.anonrouter.ai";
const phalaPolicy = {
  platformKind: "phala-dstack-kms", source: "synthetic-phala-tuple-vectors", version: "1", origins: [PHALA_ORIGIN],
  releaseTuples: [{
    tupleId: "phala-release", releaseId: "content@phala", appId: APP_ID, composeHash: phalaCompose.hash,
    mrTd: "3f".repeat(48), mrConfigId: SYNTHETIC_MR_CONFIG_ID, rtmr0: phalaLog.rtmr0, rtmr1: phalaLog.rtmr1, rtmr2: phalaLog.rtmr2,
    osImageHash: SYNTHETIC_OS_IMAGE_HASH, keyProviderPayload: KMS_PAYLOAD, notBeforeMs: NOW - DAY, expiresAtMs: NOW + DAY
  }],
  ...floor
};
const phalaBinding = { v: 1, nonce: NONCE, app_id: APP_ID, instance_id: INSTANCE_ID, compose_hash: phalaCompose.hash,
  release_id: "content@phala", origin: PHALA_ORIGIN, key_alg: "x25519", public_key: "ab".repeat(32), transport: "in-tee-tls", tls_spki_sha256: SPKI };
const phalaEvidence = {
  binding: phalaBinding,
  quote: buildSyntheticTdxQuote({ reportDataHex: gatewayBindingHash(phalaBinding as never), mrTd: "3f".repeat(48), mrConfigId: SYNTHETIC_MR_CONFIG_ID,
    rtmr0: phalaLog.rtmr0, rtmr1: phalaLog.rtmr1, rtmr2: phalaLog.rtmr2, rtmr3: phalaLog.rtmr3 }),
  event_log: JSON.stringify(phalaLog.events), app_compose: phalaCompose.manifest, vm_config: buildVmConfig(), issued_at_ms: NOW - 1_000
};

const tuple0 = gcpPolicy.releaseTuples[0]!;
const withTuple = (changes: Record<string, unknown>) => ({ ...gcpPolicy, releaseTuples: [{ ...tuple0, ...changes }] });
const legacyFields = { appIds: [APP_ID], composeHashes: [composeA.hash], releaseIds: ["content@a"] };

const loadCases: { name: string; policy: unknown; accepted: boolean }[] = [
  { name: "gcp tuple form", policy: gcpPolicy, accepted: true },
  { name: "phala tuple form", policy: phalaPolicy, accepted: true },
  { name: "MIXED: platformKind with independent allowlists", policy: { ...gcpPolicy, ...legacyFields }, accepted: false },
  { name: "MIXED: platformKind with a legacy platform block", policy: { ...gcpPolicy, platform: { mrTd: [FW1.mrTd] } }, accepted: false },
  { name: "MIXED: releaseTuples without platformKind", policy: (({ platformKind: _k, ...rest }) => ({ ...rest, ...legacyFields, keyProviderId: "aa", platform: {} }))(gcpPolicy), accepted: false },
  { name: "unknown platform kind", policy: { ...gcpPolicy, platformKind: "gcp-vtpm" }, accepted: false },
  { name: "VTPM: a PCR allowlist is an unknown policy field", policy: { ...gcpPolicy, vtpmPcrs: { "0": "00".repeat(32) } }, accepted: false },
  { name: "VTPM: a PCR field inside a tuple", policy: withTuple({ pcr0: "00".repeat(32) }), accepted: false },
  { name: "gcp tuple must not carry a dstack osImageHash", policy: withTuple({ osImageHash: SYNTHETIC_OS_IMAGE_HASH }), accepted: false },
  { name: "gcp tuple must not carry a key provider", policy: withTuple({ keyProviderPayload: NONE_PAYLOAD }), accepted: false },
  { name: "gcp tuple must not carry MRCONFIGID (it is required zero)", policy: withTuple({ mrConfigId: "00".repeat(48) }), accepted: false },
  { name: "gcp tuple requires tdAttributes", policy: withTuple({ tdAttributes: undefined }), accepted: false },
  { name: "gcp tuple requires xfam", policy: withTuple({ xfam: undefined }), accepted: false },
  { name: "gcp tuple with a short xfam", policy: withTuple({ xfam: "e71806" }), accepted: false },
  { name: "phala tuple must not carry xfam", policy: { ...phalaPolicy, releaseTuples: [{ ...phalaPolicy.releaseTuples[0]!, xfam: FW1.xfam }] }, accepted: false },
  { name: "gcp tuple with debug tdAttributes", policy: withTuple({ tdAttributes: "0100001000000000" }), accepted: false },
  { name: "gcp app id must be a 32-byte verity root", policy: withTuple({ appId: APP_ID }), accepted: false },
  { name: "phala tuple requires osImageHash", policy: { ...phalaPolicy, releaseTuples: [(({ osImageHash: _o, ...rest }) => rest)(phalaPolicy.releaseTuples[0]!)] }, accepted: false },
  { name: "phala tuple must not carry tdAttributes", policy: { ...phalaPolicy, releaseTuples: [{ ...phalaPolicy.releaseTuples[0]!, tdAttributes: FW1.tdAttributes }] }, accepted: false },
  { name: "phala tuple naming a non-KMS provider", policy: { ...phalaPolicy, releaseTuples: [{ ...phalaPolicy.releaseTuples[0]!, keyProviderPayload: NONE_PAYLOAD }] }, accepted: false },
  { name: "phala key provider payload that is not JSON", policy: { ...phalaPolicy, releaseTuples: [{ ...phalaPolicy.releaseTuples[0]!, keyProviderPayload: "6b6d73" }] }, accepted: false },
  { name: "missing tuple register", policy: withTuple({ rtmr2: undefined }), accepted: false },
  { name: "uppercase register hex", policy: withTuple({ rtmr1: FW1.rtmr1.toUpperCase() }), accepted: false },
  { name: "short register", policy: withTuple({ mrTd: "1a".repeat(47) }), accepted: false },
  { name: "empty validity window", policy: withTuple({ notBeforeMs: NOW, expiresAtMs: NOW }), accepted: false },
  { name: "validity window longer than 366 days", policy: withTuple({ notBeforeMs: NOW, expiresAtMs: NOW + 367 * DAY }), accepted: false },
  { name: "fractional time", policy: withTuple({ expiresAtMs: NOW + 0.5 }), accepted: false },
  { name: "unsafe integer time", policy: withTuple({ expiresAtMs: 2 ** 53 }), accepted: false },
  { name: "negative time", policy: withTuple({ notBeforeMs: -1 }), accepted: false },
  { name: "duplicate tuple ids", policy: { ...gcpPolicy, releaseTuples: [tuple0, { ...gcpPolicy.releaseTuples[1]!, tupleId: tuple0.tupleId }] }, accepted: false },
  { name: "no tuples", policy: { ...gcpPolicy, releaseTuples: [] }, accepted: false },
  { name: "too many tuples", policy: { ...gcpPolicy, releaseTuples: Array.from({ length: 65 }, (_, i) => ({ ...tuple0, tupleId: `t${i}` })) }, accepted: false },
  { name: "release label outside the binding alphabet", policy: withTuple({ releaseId: "content a" }), accepted: false }
];

interface VerifyCase {
  name: string;
  why: string;
  policy: unknown;
  evidence: unknown;
  expectations: { nonce: string; origin: string; nowMs: number; observedTlsSpki: { supplied: boolean; value: string | null };
    observedOnRetainedConnection: boolean; unqualifiedPlatformPilot: boolean };
  chainVerifier: { verified: boolean; tcbStatus: string | null } | null;
}

const retained = { nonce: NONCE, origin: ORIGIN, nowMs: NOW, observedTlsSpki: { supplied: true, value: SPKI },
  observedOnRetainedConnection: true, unqualifiedPlatformPilot: true };
const chainOk = { verified: true, tcbStatus: "UpToDate" };

const verifyInputs: VerifyCase[] = [
  { name: "gcp pilot: release A on firmware 1 over the retained socket", why: "The only shape that passes: whole tuple, native DCAP, same-socket key, explicit pilot. The unqualified boot chain stays visible as an unmet advisory.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: retained, chainVerifier: chainOk },
  { name: "gcp pilot: release B on firmware 2", why: "Tuples are OR: the second complete tuple matches on its own.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseB), expectations: retained, chainVerifier: chainOk },
  { name: "MIXED TUPLE: release B code on firmware 1", why: "Every value is individually approved somewhere, but no single tuple holds them together.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseB, fw: FW1 }), expectations: retained, chainVerifier: chainOk },
  { name: "MIXED TUPLE: release A label and verity root with release B compose", why: "The release label, verity root and compose hash must come from the same tuple.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, compose: composeB }), expectations: retained, chainVerifier: chainOk },
  { name: "MIXED TUPLE: release A verity root on release B everything else", why: "The verity root that RTMR1 commits to is part of the tuple.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseB, root: ROOT_A }), expectations: retained, chainVerifier: chainOk },
  { name: "WRONG PLATFORM: RTMR1 differs (another UKI)", why: "A kernel, command line or verity root the tuple does not name fails even with everything else approved.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, quote: { rtmr1: "77".repeat(48) } }), expectations: retained, chainVerifier: chainOk },
  { name: "WRONG PLATFORM: TD attributes differ", why: "The exact TD attributes are part of the tuple.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, quote: { tdAttributes: "0000000000000000" } }), expectations: retained, chainVerifier: chainOk },
  { name: "WRONG PLATFORM: XFAM differs (extra CPU state enabled)", why: "XFAM selects the extended CPU state the TD may use; a boot with a different feature set matches no tuple.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, quote: { xfam: "e71a060000000000" } }), expectations: retained, chainVerifier: chainOk },
  { name: "WRONG PLATFORM: MRCONFIGID set", why: "Owner-supplied configuration registers must be zero.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, quote: { mrConfigId: "01".repeat(48) } }), expectations: retained, chainVerifier: chainOk },
  { name: "WRONG PLATFORM: MROWNER set", why: "Owner-supplied configuration registers must be zero.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, quote: { mrOwner: "02".repeat(48) } }), expectations: retained, chainVerifier: chainOk },
  { name: "RTMR3 EXTENDED", why: "This guest measures no runtime events; any RTMR3 extension is unexplained code or configuration.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, quote: { rtmr3: "99".repeat(48) } }), expectations: retained, chainVerifier: chainOk },
  { name: "INSTANCE ID not derived from the boot key", why: "The per-boot identity must be SHA-256 of the boot key the binding carries.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, binding: { public_key: otherBootKey } }), expectations: retained, chainVerifier: chainOk },
  { name: "BOOT KEY not ed25519", why: "The GCP boot key is Ed25519; another algorithm is a different protocol.",
    policy: gcpPolicy, evidence: gcpEvidence({ ...releaseA, binding: { key_alg: "x25519" } }), expectations: retained, chainVerifier: chainOk },
  { name: "EXPIRED TUPLE", why: "A tuple's own expiry ends acceptance even when every measurement matches.",
    policy: { ...gcpPolicy, releaseTuples: [{ ...tuple0, notBeforeMs: NOW - 2 * DAY, expiresAtMs: NOW - DAY }] }, evidence: gcpEvidence(releaseA), expectations: retained, chainVerifier: chainOk },
  { name: "NOT YET VALID TUPLE", why: "A tuple cannot be used before its window opens.",
    policy: { ...gcpPolicy, releaseTuples: [{ ...tuple0, notBeforeMs: NOW + 1, expiresAtMs: NOW + DAY }] }, evidence: gcpEvidence(releaseA), expectations: retained, chainVerifier: chainOk },
  { name: "WRONG KEY: another node's certificate on this socket", why: "The quote binds a different per-boot TLS key than the connection presents.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: { ...retained, observedTlsSpki: { supplied: true, value: OTHER_NODE_SPKI } }, chainVerifier: chainOk },
  { name: "WRONG KEY: no observed certificate", why: "For GCP an unobserved certificate is a failure, never an advisory gap.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: { ...retained, observedTlsSpki: { supplied: false, value: null } }, chainVerifier: chainOk },
  { name: "SEPARATE CONNECTION: matching SPKI not observed on the retained socket", why: "A certificate seen on another connection may belong to another node behind the balancer.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: { ...retained, observedOnRetainedConnection: false }, chainVerifier: chainOk },
  { name: "NO PILOT OPT-IN", why: "The native boot chain is unqualified, so an explicit caller acknowledgement is required.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: { ...retained, unqualifiedPlatformPilot: false }, chainVerifier: chainOk },
  { name: "NO NATIVE DCAP", why: "Without an Intel chain verifier there is no substitute: GCP fails closed.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: retained, chainVerifier: null },
  { name: "TCB not UpToDate", why: "The signature can chain while the platform is out of date.",
    policy: gcpPolicy, evidence: gcpEvidence(releaseA), expectations: retained, chainVerifier: { verified: true, tcbStatus: "OutOfDate" } },
  { name: "phala tuple form, full replay", why: "The tuple form also serves the existing platform, with its full dstack replay and KMS provider.",
    policy: phalaPolicy, evidence: phalaEvidence,
    expectations: { nonce: NONCE, origin: PHALA_ORIGIN, nowMs: NOW, observedTlsSpki: { supplied: true, value: SPKI }, observedOnRetainedConnection: false, unqualifiedPlatformPilot: false },
    chainVerifier: chainOk },
  { name: "phala tuple form, another KMS", why: "The exact key-provider payload is part of the Phala tuple.",
    policy: { ...phalaPolicy, releaseTuples: [{ ...phalaPolicy.releaseTuples[0]!, keyProviderPayload: bytesToHex(utf8Encode(JSON.stringify({ name: "kms", id: "bb".repeat(33) }))) }] },
    evidence: phalaEvidence,
    expectations: { nonce: NONCE, origin: PHALA_ORIGIN, nowMs: NOW, observedTlsSpki: { supplied: true, value: SPKI }, observedOnRetainedConnection: false, unqualifiedPlatformPilot: false },
    chainVerifier: chainOk }
];

const verifyCases = verifyInputs.map((input) => {
  const policy = loadGatewayPolicy(input.policy);
  const e = input.expectations;
  const result = verifyGatewayAttestation(input.evidence as GatewayAttestationEvidence, {
    nonce: e.nonce, origin: e.origin, policy, now: e.nowMs,
    ...(e.observedTlsSpki.supplied ? { observedTlsSpkiSha256: e.observedTlsSpki.value } : {}),
    observedOnRetainedConnection: e.observedOnRetainedConnection,
    unqualifiedPlatformPilot: e.unqualifiedPlatformPilot,
    ...(input.chainVerifier ? { chainVerifier: { implementation: "vector-stub", verifyChain: () => ({
      verified: input.chainVerifier!.verified, ...(input.chainVerifier!.tcbStatus ? { tcbStatus: input.chainVerifier!.tcbStatus } : {}) }) } } : {})
  });
  return {
    ...input,
    expected: {
      status: result.status,
      verificationLevel: result.verificationLevel,
      reason: result.reason,
      failedRequiredChecks: result.checks.filter((c) => c.required && !c.passed).map((c) => c.name),
      unmetAdvisoryChecks: result.checks.filter((c) => !c.required && !c.passed).map((c) => c.name),
      releaseTupleDetail: result.checks.find((c) => c.name === "release_tuple_matched")?.detail ?? null
    }
  };
});

if (bytesToHex(sha256(hexToBytes(SYNTHETIC_GCP_BOOT_KEY))) !== SYNTHETIC_GCP_INSTANCE_ID) throw new Error("fixture boot key drift");

// Signed approvals, from ephemeral keys that exist only while this runs.
const secrets = [ed25519.utils.randomSecretKey(), ed25519.utils.randomSecretKey()];
const root: GatewayPolicyAuthority = {
  schema: "anonrouter.gateway-policy-authority/v1", enabled: true, authority: "synthetic-tuple-vectors/v1",
  url: "https://policy.example/gateway-policy.json", origins: [ORIGIN, PHALA_ORIGIN], threshold: 2,
  keys: { "test-0": bytesToHex(ed25519.getPublicKey(secrets[0]!)), "test-1": bytesToHex(ed25519.getPublicKey(secrets[1]!)) },
  minSequence: 1, maxLifetimeMs: 7 * DAY, refreshMs: 300_000, maxStaleMs: 3_600_000
};
function envelope(policy: Record<string, unknown>) {
  const manifestSha256 = "ab".repeat(32);
  const payload = canonicalGatewayPolicyJson({ schema: "anonrouter.gateway-policy/v1", authority: root.authority, sequence: 1,
    issuedAtMs: NOW - 1_000, expiresAtMs: NOW + DAY, manifestSha256,
    policy: { ...policy, source: `anonrouter-release-manifest-sha256:${manifestSha256}` } });
  const signatures = secrets.map((secret, i) => ({ keyId: `test-${i}`,
    signature: bytesToHex(ed25519.sign(utf8Encode(GATEWAY_POLICY_DOMAIN + payload), secret)) }));
  return { schema: "anonrouter.gateway-policy-envelope/v1", payload, signatures };
}
const signedCases = [
  { name: "unqualified gcp-tdx-native approval is refused even with valid signatures", origin: ORIGIN, envelope: envelope(gcpPolicy), accepted: false },
  { name: "phala tuple-form approval is accepted", origin: PHALA_ORIGIN, envelope: envelope(phalaPolicy), accepted: true }
];
for (const c of signedCases) {
  let accepted = true;
  try { verifySignedGatewayPolicy(c.envelope, root, c.origin, NOW); } catch { accepted = false; }
  if (accepted !== c.accepted) throw new Error(`signed case disagrees with generator expectation: ${c.name}`);
}
for (const c of loadCases) {
  let accepted = true;
  try { loadGatewayPolicy(c.policy); } catch { accepted = false; }
  if (accepted !== c.accepted) throw new Error(`load case disagrees with generator expectation: ${c.name}`);
}

writeFileSync(out, `${JSON.stringify({
  _readme: [
    "Tuple-form gateway policy vectors, generated by js/confidential/scripts/gen-gateway-tuple-vectors.ts.",
    "SYNTHETIC ONLY: registers, key-provider payloads, evidence and signing keys are invented test inputs;",
    "nothing here is a Google firmware value, an AnonRouter production pin or an Intel-signed quote.",
    "Both languages must load, verify and signature-check these exact bytes to the recorded outcome."
  ],
  nowMs: NOW,
  signingRoot: root,
  loadCases,
  verifyCases,
  signedCases
}, null, 2)}\n`);
console.log(`wrote ${out}: ${loadCases.length} load, ${verifyCases.length} verify, ${signedCases.length} signed cases`);
