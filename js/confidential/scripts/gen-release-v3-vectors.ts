// Generate shared/vectors/release-policy-v3.json.
//
// The owner-signed release policy v3 is how both SDKs verify AnonRouter's GCP
// content nodes, so both languages must reach the same decision over the same
// bytes. This file pins:
//
//   backendKat       the backend's own signed envelopes and digests (an
//                    implementation independent of this SDK), copied from
//                    scripts/fixtures/backend-release-v3-kat.json
//   policyCases      envelopes (and a held checkpoint) and the exact verified
//                    facts or refusal code: signatures, rollback, fork,
//                    revocation reversal, tcbGrace, requireGcePzid
//   attestationCases complete synthetic evidence, a signed policy and the
//                    exact verdict, check by check (MROWNER rules, PZID,
//                    revocation, requireGcePzid, tcbGrace)
//
//   npx tsx scripts/gen-release-v3-vectors.ts
//
// EVERYTHING HERE IS SYNTHETIC: deterministic seeds 0x11.. and 0x22.., invented
// registers and VM identities. Nothing is a production key, pin or measurement.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "../src/bytes.js";
import {
  releaseEnvelopeV3Message, releaseOwnerRootSha256, releasePolicyV3GatewayPolicy, releaseTupleDigest,
  ReleasePolicyV3Error, verifyReleasePolicyV3, type ReleasePolicyV3Checkpoint, type ReleasePolicyV3Trust
} from "../src/gateway/release-v3.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..", "..");
const read = (path: string) => JSON.parse(readFileSync(resolve(root, path), "utf8"));
const backendKat = read("scripts/fixtures/backend-release-v3-kat.json");
const pzid = read("shared/vectors/gce-pzid.json");
const tupleVectors = read("shared/vectors/gateway-release-tuples.json");

const USB_SEED = new Uint8Array(32).fill(0x11);
const LAPTOP_SEED = new Uint8Array(32).fill(0x22);
const OTHER_SEED = new Uint8Array(32).fill(0x33);
const DEPLOYMENT_ID = "gcp-content-qualification";
const GROUP_ID = "release-owner-qualification";
const ZERO = "00".repeat(48);
const keys = [
  { keyId: "custodian.prod.usb" as const, publicKey: bytesToHex(ed25519.getPublicKey(USB_SEED)) },
  { keyId: "custodian.prod.laptop" as const, publicKey: bytesToHex(ed25519.getPublicKey(LAPTOP_SEED)) }
];
const trust: ReleasePolicyV3Trust = {
  deploymentId: DEPLOYMENT_ID, groupId: GROUP_ID, keys,
  ownerRootSha256: releaseOwnerRootSha256({ deploymentId: DEPLOYMENT_ID, groupId: GROUP_ID, keys }),
  minimumPolicySequence: 1
};

function sign(payload: unknown, options: { seeds?: Uint8Array[]; role?: "release-policy" | "generation"; groupId?: string;
  ownerRootSha256?: string } = {}) {
  const role = options.role ?? "release-policy";
  const groupId = options.groupId ?? GROUP_ID;
  const owner = options.ownerRootSha256 ?? trust.ownerRootSha256;
  const message = releaseEnvelopeV3Message(role, groupId, owner, payload);
  const seeds = options.seeds ?? [USB_SEED, LAPTOP_SEED];
  return { protocol: "anonrouter-content-release-envelope-v3", role, groupId, ownerRootSha256: owner, payload,
    signatures: seeds.map((seed, index) => ({ keyId: keys[index]!.keyId, signature: bytesToHex(ed25519.sign(message, seed)) })) };
}

const tupleA = { tupleId: "release-a.fw1", mrTd: "1a".repeat(48), mrConfigId: ZERO, mrOwner: ZERO, mrOwnerConfig: ZERO,
  rtmr0: "2b".repeat(48), rtmr1: "3c".repeat(48), rtmr2: "4d".repeat(48), rtmr3: ZERO,
  tdAttributes: "0000001000000000", xfam: "e718060000000000" };
const tupleB = { ...tupleA, tupleId: "release-b.fw2", mrTd: "5e".repeat(48), rtmr0: "6f".repeat(48) };
const reference = pzid.vectors[1];
const otherVm = pzid.vectors[0];
const RULE = { kind: "gce-pzid", projectNumber: reference.projectNumber, zones: ["us-west1-a", "us-west1-b", "us-west1-c"] };
const c3A = { ...tupleA, tupleId: "release-a.c3", mrOwnerRule: RULE };
const digestA = releaseTupleDigest(tupleA);

const ISSUED = 1791240600000;
const DAY = 86_400_000;
const base = { protocol: "anonrouter-content-node-bootstrap-v1", kind: "content-node-release-policy",
  deploymentId: DEPLOYMENT_ID, revokedGenerations: [] as string[], minimumGenerationRevision: 1,
  maxEvidenceAgeMs: 300000, tcbStatus: "UpToDate" };
const payload1 = { ...base, sequence: 1, issuedAtMs: ISSUED, tuples: [tupleA, tupleB], revokedTuples: [] as string[] };
const payload2 = { ...base, sequence: 2, issuedAtMs: ISSUED + DAY, tuples: [tupleB], revokedTuples: [digestA] };
const grace = { statuses: ["OutOfDate"], advisoryIds: ["INTEL-SA-01312", "INTEL-SA-01367"], notAfterMs: ISSUED + 30 * DAY };
const envelope1 = sign(payload1);
const envelope2 = sign(payload2);
const v1 = verifyReleasePolicyV3(envelope1, trust);
const v2 = verifyReleasePolicyV3(envelope2, trust);
const checkpoint = (v: { sequence: number; policySha256: string; revokedTuples: string[] }): ReleasePolicyV3Checkpoint =>
  ({ sequence: v.sequence, policySha256: v.policySha256, revokedTuples: [...v.revokedTuples] });

type PolicyCase = { name: string; envelope: unknown; minimumPolicySequence?: number; previous?: ReleasePolicyV3Checkpoint };
const policyCaseInputs: PolicyCase[] = [
  { name: "sequence 1 with two tuples", envelope: envelope1 },
  { name: "sequence 2 revokes tuple A", envelope: envelope2, previous: checkpoint(v1) },
  { name: "one signature only", envelope: { ...envelope1, signatures: [envelope1.signatures[0]] } },
  { name: "signatures swapped", envelope: { ...envelope1, signatures: [...envelope1.signatures].reverse() } },
  { name: "wrong usb signer", envelope: sign(payload1, { seeds: [OTHER_SEED, LAPTOP_SEED] }) },
  { name: "payload changed after signing", envelope: { ...envelope1, payload: { ...payload1, sequence: 9 } } },
  { name: "wrong group", envelope: sign(payload1, { groupId: "release-owner-other" }) },
  { name: "wrong owner root", envelope: sign(payload1, { ownerRootSha256: "ab".repeat(32) }) },
  { name: "generation role", envelope: sign(payload1, { role: "generation" }) },
  { name: "wrong deployment", envelope: sign({ ...payload1, deploymentId: "gcp-content-other" }) },
  { name: "unknown payload field", envelope: sign({ ...payload1, fleetBounds: 3 }) },
  { name: "tcbStatus not UpToDate", envelope: sign({ ...payload1, tcbStatus: "OutOfDate" }) },
  { name: "approves a tuple it revokes", envelope: sign({ ...payload1, revokedTuples: [digestA] }) },
  { name: "revokedTuples unsorted", envelope: sign({ ...payload2, revokedTuples: ["ff".repeat(32), digestA] }) },
  { name: "duplicate tupleId", envelope: sign({ ...payload1, tuples: [tupleA, { ...tupleB, tupleId: tupleA.tupleId }] }) },
  { name: "maxEvidenceAgeMs above 300000", envelope: sign({ ...payload1, maxEvidenceAgeMs: 300001 }) },
  { name: "rollback below the held sequence", envelope: envelope1, previous: checkpoint(v2) },
  { name: "rollback below the minimum sequence", envelope: envelope1, minimumPolicySequence: 2 },
  { name: "fork at the held sequence", envelope: sign({ ...payload1, issuedAtMs: ISSUED + 1 }), previous: checkpoint(v1) },
  { name: "same policy again", envelope: envelope1, previous: checkpoint(v1) },
  { name: "revocation reversed", envelope: sign({ ...payload1, sequence: 3 }), previous: checkpoint(v2) },
  { name: "gce-pzid rule tuple", envelope: sign({ ...payload1, tuples: [c3A] }) },
  { name: "gce-pzid rule with nonzero mrOwner", envelope: sign({ ...payload1, tuples: [{ ...c3A, mrOwner: "11".repeat(48) }] }) },
  { name: "gce-pzid rule zones unsorted", envelope: sign({ ...payload1, tuples: [{ ...c3A, mrOwnerRule: { ...RULE, zones: ["us-west1-b", "us-west1-a"] } }] }) },
  { name: "tcbGrace accepted", envelope: sign({ ...payload1, tcbGrace: grace }) },
  { name: "tcbGrace with no statuses", envelope: sign({ ...payload1, tcbGrace: { ...grace, statuses: [] } }) },
  { name: "tcbGrace at the 90 day bound", envelope: sign({ ...payload1, tcbGrace: { ...grace, notAfterMs: ISSUED + 90 * DAY } }) },
  { name: "tcbGrace beyond 90 days", envelope: sign({ ...payload1, tcbGrace: { ...grace, notAfterMs: ISSUED + 90 * DAY + 1 } }) },
  { name: "tcbGrace not forward", envelope: sign({ ...payload1, tcbGrace: { ...grace, notAfterMs: ISSUED } }) },
  { name: "tcbGrace lists Revoked", envelope: sign({ ...payload1, tcbGrace: { ...grace, statuses: ["Revoked"] } }) },
  { name: "tcbGrace lists UpToDate", envelope: sign({ ...payload1, tcbGrace: { ...grace, statuses: ["UpToDate"] } }) },
  { name: "tcbGrace statuses unsorted", envelope: sign({ ...payload1, tcbGrace: { ...grace, statuses: ["SWHardeningNeeded", "OutOfDate"] } }) },
  { name: "tcbGrace duplicate status", envelope: sign({ ...payload1, tcbGrace: { ...grace, statuses: ["OutOfDate", "OutOfDate"] } }) },
  { name: "tcbGrace without advisories", envelope: sign({ ...payload1, tcbGrace: { ...grace, advisoryIds: [] } }) },
  { name: "tcbGrace advisories unsorted", envelope: sign({ ...payload1, tcbGrace: { ...grace, advisoryIds: ["INTEL-SA-01367", "INTEL-SA-01312"] } }) },
  { name: "tcbGrace non-Intel advisory id", envelope: sign({ ...payload1, tcbGrace: { ...grace, advisoryIds: ["CVE-2026-00001"] } }) },
  { name: "tcbGrace 65 advisories", envelope: sign({ ...payload1, tcbGrace: { ...grace,
    advisoryIds: Array.from({ length: 65 }, (_, i) => `INTEL-SA-${String(10_000 + i)}`) } }) },
  { name: "tcbGrace extra field", envelope: sign({ ...payload1, tcbGrace: { ...grace, fmspc: "20a06d080000" } }) },
  { name: "tcbGrace null", envelope: sign({ ...payload1, tcbGrace: null }) },
  { name: "requireGcePzid true", envelope: sign({ ...payload1, tuples: [c3A], requireGcePzid: true }) },
  { name: "requireGcePzid false", envelope: sign({ ...payload1, tuples: [c3A], requireGcePzid: false }) },
  { name: "requireGcePzid not boolean", envelope: sign({ ...payload1, tuples: [c3A], requireGcePzid: "true" }) }
];

function policyExpectation(input: PolicyCase) {
  const caseTrust = { ...trust, minimumPolicySequence: input.minimumPolicySequence ?? 1 };
  try {
    const v = verifyReleasePolicyV3(input.envelope, caseTrust, input.previous);
    return { ok: { sequence: v.sequence, policySha256: v.policySha256, tupleDigests: v.tuples.map((t) => t.tupleDigest),
      revokedTuples: v.revokedTuples, tcbGrace: v.tcbGrace ?? null, requireGcePzid: v.requireGcePzid ?? null } };
  } catch (error) {
    if (error instanceof ReleasePolicyV3Error) return { refusal: error.code };
    throw error;
  }
}

// --- attestation cases --------------------------------------------------------
const caseA = tupleVectors.verifyCases[0];
const MR_OWNER_HEX_OFFSET = 280 * 2;
const withMrOwner = (quote: string, mrOwner: string) =>
  quote.slice(0, MR_OWNER_HEX_OFFSET) + mrOwner + quote.slice(MR_OWNER_HEX_OFFSET + 96);
const c3Quote = withMrOwner(caseA.evidence.quote, reference.mrOwner);
const e = caseA.expectations;

type AttestationCase = { name: string; payload: Record<string, unknown>; quote: string; gcePzid?: unknown };
const attestationInputs: AttestationCase[] = [
  { name: "C4 zero rule: exact registers", payload: { ...payload1 }, quote: caseA.evidence.quote },
  { name: "C3 rule without a PZID: unverified identity", payload: { ...payload1, tuples: [c3A] }, quote: c3Quote },
  { name: "C3 rule with its PZID: verified identity", payload: { ...payload1, tuples: [c3A] }, quote: c3Quote, gcePzid: reference.payload },
  { name: "C3 rule with another VM's PZID", payload: { ...payload1, tuples: [c3A] }, quote: c3Quote, gcePzid: otherVm.payload },
  { name: "C3 rule with a malformed PZID", payload: { ...payload1, tuples: [c3A] }, quote: c3Quote, gcePzid: "{}" },
  { name: "C3 VM outside the rule's project", payload: { ...payload1, tuples: [{ ...c3A, mrOwnerRule: { ...RULE, projectNumber: "999000111222" } }] },
    quote: c3Quote, gcePzid: reference.payload },
  { name: "C3 VM outside the rule's zones", payload: { ...payload1, tuples: [{ ...c3A, mrOwnerRule: { ...RULE, zones: ["europe-west4-a"] } }] },
    quote: c3Quote, gcePzid: reference.payload },
  { name: "nonzero MROWNER and no rule", payload: { ...payload1 }, quote: c3Quote },
  { name: "zero MROWNER against a rule-only policy", payload: { ...payload1, tuples: [c3A] }, quote: caseA.evidence.quote },
  { name: "two rule tuples match the same VM", payload: { ...payload1, tuples: [c3A, { ...c3A, tupleId: "release-a.c3-narrow",
    mrOwnerRule: { ...RULE, zones: ["us-west1-a"] } }] }, quote: c3Quote, gcePzid: reference.payload },
  { name: "revoked tuple A after sequence 2", payload: { ...payload2 }, quote: caseA.evidence.quote },
  { name: "requireGcePzid without a PZID", payload: { ...payload1, tuples: [c3A], requireGcePzid: true }, quote: c3Quote },
  { name: "requireGcePzid with the PZID", payload: { ...payload1, tuples: [c3A], requireGcePzid: true }, quote: c3Quote, gcePzid: reference.payload },
  { name: "requireGcePzid on a C4 zero-MROWNER tuple", payload: { ...payload1, requireGcePzid: true }, quote: caseA.evidence.quote },
  { name: "tcbGrace policy still verifies UpToDate exactly", payload: { ...payload1, tcbGrace: grace }, quote: caseA.evidence.quote }
];

function attestationExpectation(input: AttestationCase, envelope: unknown, evidence: GatewayAttestationEvidence) {
  const policy = releasePolicyV3GatewayPolicy(verifyReleasePolicyV3(envelope, trust), [e.origin]);
  const verdict = verifyGatewayAttestation(evidence, { nonce: e.nonce, origin: e.origin, policy, now: e.nowMs,
    observedTlsSpkiSha256: e.observedTlsSpki.value, observedOnRetainedConnection: true,
    chainVerifier: { implementation: "vector-stub", verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" }) } });
  return { status: verdict.status, verificationLevel: verdict.verificationLevel, reason: verdict.reason,
    instanceIdentity: verdict.instanceIdentity, gceInstance: verdict.gceInstance,
    checks: verdict.checks.map((c) => [c.name, c.passed, c.required]) };
}

const policyCases = policyCaseInputs.map((input) => ({ ...input, expected: policyExpectation(input) }));
const attestationCases = attestationInputs.map((input) => {
  const envelope = sign(input.payload);
  const evidence = { ...caseA.evidence, quote: input.quote, ...(input.gcePzid === undefined ? {} : { gce_pzid: input.gcePzid }) };
  return { name: input.name, envelope, evidence, expected: attestationExpectation(input, envelope, evidence as GatewayAttestationEvidence) };
});

const out = resolve(root, "shared", "vectors", "release-policy-v3.json");
writeFileSync(out, `${JSON.stringify({
  _readme: [
    "Owner-signed release policy v3 known answers, loaded identically by the JS and Python suites.",
    "Generated by js/confidential/scripts/gen-release-v3-vectors.ts. Everything is synthetic:",
    "seeds 0x11.. (custodian.prod.usb) and 0x22.. (custodian.prod.laptop), invented registers and",
    "VM identities. backendKat comes from the AnonRouter backend's own implementation.",
    "attestationCases: verify the envelope against `trust`, build the gcp-tdx-native gateway policy for",
    "`expectations.origin`, then verify `evidence` on the retained connection with a chain verifier that",
    "reports verified/UpToDate. checks are [name, passed, required] in order."
  ],
  trust,
  backendKat,
  policyCases,
  expectations: { nonce: e.nonce, origin: e.origin, nowMs: e.nowMs, observedTlsSpki: e.observedTlsSpki.value },
  attestationCases
}, null, 2)}\n`);
console.log(`wrote ${policyCases.length} policy and ${attestationCases.length} attestation cases to ${out}`);
