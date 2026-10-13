// GCE C3 MROWNER: the owner-signed gce-pzid tuple rule of release policy v3.
//
// shared/vectors/gce-pzid.json is byte-identical to the server's
// native/gcp-content-guest/tests/vectors/gce-pzid.json (anonrouter commit
// cab4bf32): Go-produced PZID payloads and digests, plus a policy carrying both
// MROWNER rules with its server-computed tuple digests and policy SHA-256.
//
// Quotes are the shared synthetic GCP quotes with only the MROWNER bytes
// replaced. MROWNER is outside report_data, so the binding still verifies; the
// chain verifier is a stub, so nothing here depends on Intel collateral.

import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import pzidVectors from "../../../shared/vectors/gce-pzid.json" with { type: "json" };
import tupleVectors from "../../../shared/vectors/gateway-release-tuples.json" with { type: "json" };
import { bytesToHex } from "../src/bytes.js";
import {
  gceInstanceFromMrOwner, gcePzidDigestHex, gcePzidPayload, isGceUint64, isGceZone, parseGcePzid, validateGceMrOwnerRule,
  GCE_ZERO_MR_OWNER
} from "../src/gateway/gce-pzid.js";
import { assertGatewayPlatformSecurityFloor, validateGatewayMeasuredTupleV3, type GatewayMeasurementPolicy } from "../src/gateway/policy.js";
import { releasePolicySha256 } from "../src/gateway/release-v3-canonical.js";
import {
  releaseEnvelopeV3Message, releaseOwnerRootSha256, releasePolicyV3GatewayPolicy, releaseTupleDigest, ReleasePolicyV3Error,
  verifyReleasePolicyV3, type ReleasePolicyV3Trust
} from "../src/gateway/release-v3.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";

const USB_SEED = new Uint8Array(32).fill(0x11);
const LAPTOP_SEED = new Uint8Array(32).fill(0x22);
const DEPLOYMENT_ID = pzidVectors.policy.payload.deploymentId;
const GROUP_ID = "release-owner-qualification";
const ORIGIN = "https://content.gcp.example";
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
function sign(payload: unknown) {
  const message = releaseEnvelopeV3Message("release-policy", GROUP_ID, trust.ownerRootSha256, payload);
  return { protocol: "anonrouter-content-release-envelope-v3", role: "release-policy", groupId: GROUP_ID,
    ownerRootSha256: trust.ownerRootSha256, payload,
    signatures: [USB_SEED, LAPTOP_SEED].map((seed, index) => ({ keyId: keys[index]!.keyId, signature: bytesToHex(ed25519.sign(message, seed)) })) };
}
function refusal(run: () => unknown): string {
  try { run(); } catch (error) {
    if (error instanceof ReleasePolicyV3Error) return error.code;
    throw error;
  }
  throw new Error("expected a refusal");
}

// The release 1060 C3 reference boot (vector 1) and the production control VM
// (vector 0): same project and zone, different instances.
const reference = pzidVectors.vectors[1]!;
const otherVm = pzidVectors.vectors[0]!;
const PROJECT = reference.projectNumber;
const RULE = { kind: "gce-pzid" as const, projectNumber: PROJECT, zones: ["us-west1-a", "us-west1-b", "us-west1-c"] };

// The shared synthetic quotes; tupleA/tupleB are exactly their registers.
const caseA = tupleVectors.verifyCases[0]!;
const caseB = tupleVectors.verifyCases[1]!;
const tupleA = { tupleId: "release-a.fw1", mrTd: "1a".repeat(48), mrConfigId: ZERO, mrOwner: ZERO, mrOwnerConfig: ZERO,
  rtmr0: "2b".repeat(48), rtmr1: "3c".repeat(48), rtmr2: "4d".repeat(48), rtmr3: ZERO,
  tdAttributes: "0000001000000000", xfam: "e718060000000000" };
const tupleB = { ...tupleA, tupleId: "release-b.fw2", mrTd: "5e".repeat(48), rtmr0: "6f".repeat(48) };
const c3A = { ...tupleA, tupleId: "release-a.c3", mrOwnerRule: RULE };

const basePayload = { protocol: "anonrouter-content-node-bootstrap-v1", kind: "content-node-release-policy",
  deploymentId: DEPLOYMENT_ID, sequence: 1, issuedAtMs: 1791240600000, revokedTuples: [] as string[],
  revokedGenerations: [] as string[], minimumGenerationRevision: 1, maxEvidenceAgeMs: 300000, tcbStatus: "UpToDate" };
const policyWith = (tuples: unknown[], extra: Record<string, unknown> = {}): GatewayMeasurementPolicy =>
  releasePolicyV3GatewayPolicy(verifyReleasePolicyV3(sign({ ...basePayload, tuples, ...extra }), trust), [ORIGIN]);

// MROWNER sits at byte 280 of a v4 quote (48 header + 232 into the TD report).
const MR_OWNER_HEX_OFFSET = 280 * 2;
function withMrOwner(quote: string, mrOwner: string): string {
  return quote.slice(0, MR_OWNER_HEX_OFFSET) + mrOwner + quote.slice(MR_OWNER_HEX_OFFSET + 96);
}
function withRegister(quote: string, byteOffset: number, value: string): string {
  return quote.slice(0, byteOffset * 2) + value + quote.slice(byteOffset * 2 + value.length);
}
type Case = typeof caseA;
function attest(testCase: Case, policy: GatewayMeasurementPolicy, evidence: Partial<GatewayAttestationEvidence> = {}) {
  const e = testCase.expectations;
  return verifyGatewayAttestation({ ...(testCase.evidence as unknown as GatewayAttestationEvidence), ...evidence }, {
    nonce: e.nonce, origin: e.origin, policy, now: e.nowMs, observedTlsSpkiSha256: e.observedTlsSpki.value,
    observedOnRetainedConnection: true, unqualifiedPlatformPilot: true,
    chainVerifier: { implementation: "vector-stub", verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" }) }
  });
}
const c3QuoteA = withMrOwner(caseA.evidence.quote, reference.mrOwner);
const failedRequired = (result: ReturnType<typeof attest>) => result.checks.filter((c) => c.required && !c.passed).map((c) => c.name);
const checkNamed = (result: ReturnType<typeof attest>, name: string) => result.checks.find((c) => c.name === name);

describe("shared PZID vectors (Go-produced)", () => {
  it("reproduces every payload and MROWNER digest byte for byte", () => {
    for (const vector of pzidVectors.vectors) {
      const payload = gcePzidPayload(vector);
      expect(payload).toBe(vector.payload);
      expect(gcePzidDigestHex(payload)).toBe(vector.mrOwner);
    }
  });

  it("parses each nonzero PZID back to its fields, and binds it only to its own MROWNER", () => {
    for (const vector of pzidVectors.vectors.filter((v) => v.projectNumber !== "0")) {
      const fields = { projectNumber: vector.projectNumber, zone: vector.zone, instanceId: vector.instanceId };
      expect(parseGcePzid(vector.payload)).toEqual(fields);
      expect(gceInstanceFromMrOwner(vector.payload, vector.mrOwner)).toEqual(fields);
      expect(gceInstanceFromMrOwner(vector.payload, vector.mrOwner.toUpperCase())).toEqual(fields);
      expect(gceInstanceFromMrOwner(vector.payload, otherVm.mrOwner === vector.mrOwner ? reference.mrOwner : otherVm.mrOwner)).toBeNull();
      expect(gceInstanceFromMrOwner(vector.payload, GCE_ZERO_MR_OWNER)).toBeNull();
    }
    // GCE never assigns 0: a zero project or instance hashes but never binds.
    const zero = pzidVectors.vectors.find((v) => v.projectNumber === "0")!;
    expect(parseGcePzid(zero.payload)).toBeNull();
    expect(gceInstanceFromMrOwner(zero.payload, zero.mrOwner)).toBeNull();
  });

  it("keeps uint64 numbers above 2^53 exact", () => {
    const max = pzidVectors.vectors.find((v) => v.instanceId === "18446744073709551615")!;
    expect(parseGcePzid(max.payload)?.instanceId).toBe("18446744073709551615");
    expect(isGceUint64("18446744073709551616")).toBe(false);
  });

  it("refuses every refused zone and number", () => {
    for (const zone of pzidVectors.refusedZones) {
      expect(isGceZone(zone)).toBe(false);
      expect(() => gcePzidPayload({ projectNumber: "1", zone, instanceId: "1" })).toThrow();
      expect(parseGcePzid(`{"instanceId":1,"numericalProjectId":1,"zone":${JSON.stringify(zone)}}`)).toBeNull();
    }
    for (const number of pzidVectors.refusedNumbers) {
      expect(isGceUint64(number)).toBe(false);
      expect(() => gcePzidPayload({ projectNumber: number, zone: "a", instanceId: "1" })).toThrow();
      expect(parseGcePzid(`{"instanceId":${number},"numericalProjectId":1,"zone":"a"}`)).toBeNull();
    }
  });

  it("parses only the exact canonical form", () => {
    for (const variant of [
      reference.payload.replace(":", ": "),
      ` ${reference.payload}`,
      `${reference.payload}\n`,
      reference.payload.replace('"zone":"us-west1-a"', '"zone":"us-west1-a","extra":1'),
      `{"numericalProjectId":${PROJECT},"instanceId":${reference.instanceId},"zone":"us-west1-a"}`,
      JSON.parse(reference.payload) as unknown,
      "x".repeat(300)
    ]) expect(parseGcePzid(variant)).toBeNull();
  });
});

describe("the owner-signed gce-pzid rule in a release policy", () => {
  it("matches the server's tuple digests and policy SHA-256 for both rules", () => {
    const { payload, tupleDigests, policySha256 } = pzidVectors.policy;
    const tuples = payload.tuples.map((tuple, index) => validateGatewayMeasuredTupleV3(tuple, index));
    expect(Object.fromEntries(tuples.map((tuple) => [tuple.tupleId, releaseTupleDigest(tuple)]))).toEqual(tupleDigests);
    expect(releasePolicySha256(payload)).toBe(policySha256);
    const verified = verifyReleasePolicyV3(sign(payload), trust);
    expect(verified.policySha256).toBe(policySha256);
    expect(verified.tuples.map((tuple) => tuple.tupleDigest)).toEqual([tupleDigests["release-a"], tupleDigests["release-c3"]]);
    expect(verified.tuples[1]!.mrOwnerRule).toEqual(payload.tuples[1]!.mrOwnerRule);
    expect(verified.tuples[0]!.mrOwnerRule).toBeUndefined();
  });

  it("a rule-less tuple keeps the digest it had before the rule existed", () => {
    const { mrOwnerRule: _rule, ...plain } = c3A;
    expect(releaseTupleDigest(plain)).toBe(releaseTupleDigest({ ...tupleA, tupleId: "x" }));
    expect(releaseTupleDigest(c3A)).not.toBe(releaseTupleDigest(plain));
    expect(releaseTupleDigest({ ...c3A, mrOwnerRule: { ...RULE, zones: ["us-west1-a"] } })).not.toBe(releaseTupleDigest(c3A));
  });

  it("refuses a malformed rule, each correctly signed", () => {
    const signed = (rule: unknown, owner = ZERO) =>
      refusal(() => verifyReleasePolicyV3(sign({ ...basePayload, tuples: [{ ...tupleA, mrOwner: owner, mrOwnerRule: rule }] }), trust));
    expect(signed(RULE, reference.mrOwner)).toBe("contract_invalid");
    for (const bad of [
      { ...RULE, kind: "zero" },
      { ...RULE, projectNumber: "0" },
      { ...RULE, projectNumber: "01" },
      { ...RULE, projectNumber: "18446744073709551616" },
      { ...RULE, zones: [] },
      { ...RULE, zones: ["us-west1-b", "us-west1-a"] },
      { ...RULE, zones: ["us-west1-a", "us-west1-a"] },
      { ...RULE, zones: Array.from({ length: 9 }, (_, i) => `zone-${i}`) },
      { ...RULE, zones: ["US-west1-a"] },
      { ...RULE, extra: true },
      { kind: RULE.kind, zones: RULE.zones },
      null,
      [RULE]
    ]) expect(signed(bad)).toBe("contract_invalid");
    // A float or negative project number has no canonical encoding, so it cannot be signed.
    expect(refusal(() => sign({ ...basePayload, tuples: [{ ...tupleA, mrOwnerRule: { ...RULE, projectNumber: -1 } }] }))).toBe("contract_invalid");
    expect(() => validateGceMrOwnerRule({ ...RULE, projectNumber: 1066448738612 })).toThrow(/projectNumber/);
  });

  it("refuses a policy that approves a gce-pzid tuple it also revokes", () => {
    expect(refusal(() => verifyReleasePolicyV3(sign({ ...basePayload, tuples: [c3A], revokedTuples: [releaseTupleDigest(c3A)] }), trust)))
      .toBe("revoked_tuple_approved");
  });
});

describe("a C3 quote against a gce-pzid tuple", () => {
  const policy = policyWith([c3A]);
  const c3Case = { ...caseA, evidence: { ...caseA.evidence, quote: c3QuoteA } };

  it("without a PZID: accepted with instanceIdentity unverified, every other register matching", () => {
    const result = attest(c3Case, policy);
    expect(failedRequired(result)).toEqual([]);
    expect(result.status).toBe("ok");
    expect(result.verificationLevel).toBe("hardware-verified");
    expect(result.instanceIdentity).toBe("unverified");
    expect(result.gceInstance).toBeNull();
    expect(checkNamed(result, "release_tuple_matched")?.detail)
      .toBe("tuple=release-a.c3 policy_sequence=1 mrowner_rule=gce-pzid instance_identity=unverified");
    const identity = checkNamed(result, "gce_instance_identity");
    expect(identity).toMatchObject({ passed: false, required: false });
    expect(identity?.detail).toMatch(/project 1066448738612 zones us-west1-a,us-west1-b,us-west1-c/);
    expect(attest(c3Case, policy, { gce_pzid: null }).instanceIdentity).toBe("unverified");
  });

  it("with the node's PZID: verified, naming the VM", () => {
    const result = attest(c3Case, policy, { gce_pzid: reference.payload });
    expect(failedRequired(result)).toEqual([]);
    expect(result.status).toBe("ok");
    expect(result.instanceIdentity).toBe("verified");
    expect(result.gceInstance).toEqual({ projectNumber: PROJECT, zone: "us-west1-a", instanceId: reference.instanceId });
    expect(checkNamed(result, "gce_pzid_matches_mrowner")).toMatchObject({ passed: true, required: true });
    expect(checkNamed(result, "gce_instance_identity")).toMatchObject({ passed: true, required: true,
      detail: `projects/${PROJECT}/zones/us-west1-a/instances/${reference.instanceId}` });
    expect(checkNamed(result, "release_tuple_matched")?.detail).toMatch(/instance_identity=verified$/);
  });

  it("a presented PZID that is not this quote's refuses and never degrades to unverified", () => {
    for (const presented of [otherVm.payload, reference.payload.replace(":", ": "), { ...reference }, 1, "", reference.mrOwner]) {
      const result = attest(c3Case, policy, { gce_pzid: presented });
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("gce_pzid_matches_mrowner");
      expect(failedRequired(result)).toEqual(["gce_pzid_matches_mrowner", "release_tuple_matched"]);
      expect(result.instanceIdentity).toBeNull();
    }
  });

  it("a digest-verified VM outside the rule's project or zones refuses", () => {
    const westB = policyWith([{ ...c3A, mrOwnerRule: { ...RULE, zones: ["us-west1-b", "us-west1-c"] } }]);
    const elsewhere = policyWith([{ ...c3A, mrOwnerRule: { ...RULE, projectNumber: "123456789012" } }]);
    for (const p of [westB, elsewhere]) {
      const result = attest(c3Case, p, { gce_pzid: reference.payload });
      expect(result.reason).toBe("release_tuple_matched");
      expect(checkNamed(result, "release_tuple_matched")?.detail).toMatch(/outside every matching gce-pzid rule/);
      // Without the PZID the zone and project cannot be checked: unverified, as documented.
      expect(attest(c3Case, p).instanceIdentity).toBe("unverified");
    }
  });

  it("any other register that differs refuses, PZID or not", () => {
    // RTMR1 (byte 424) and MRCONFIGID (byte 232).
    for (const quote of [withRegister(c3QuoteA, 424, "3d".repeat(48)), withRegister(c3QuoteA, 232, "01".repeat(48))]) {
      const changed = { ...caseA, evidence: { ...caseA.evidence, quote } };
      expect(attest(changed, policy).status).toBe("failed");
      expect(attest(changed, policy, { gce_pzid: reference.payload }).status).toBe("failed");
    }
  });

  it("a zero MROWNER (a C4 boot of the same image) does not match a gce-pzid tuple", () => {
    const result = attest(caseA, policy);
    expect(result.reason).toBe("release_tuple_matched");
    expect(checkNamed(result, "release_tuple_matched")?.detail).toMatch(/MROWNER is zero/);
    expect(attest(caseA, policy, { gce_pzid: reference.payload }).reason).toBe("gce_pzid_matches_mrowner");
  });

  it("two gce-pzid tuples for one image: ambiguous without a PZID, resolved by one", () => {
    const split = policyWith([
      { ...c3A, tupleId: "release-a.c3-a", mrOwnerRule: { ...RULE, zones: ["us-west1-a"] } },
      { ...c3A, tupleId: "release-a.c3-bc", mrOwnerRule: { ...RULE, zones: ["us-west1-b", "us-west1-c"] } }
    ]);
    const ambiguous = attest(c3Case, split);
    expect(ambiguous.reason).toBe("release_tuple_matched");
    expect(checkNamed(ambiguous, "release_tuple_matched")?.detail).toMatch(/more than one/);
    const resolved = attest(c3Case, split, { gce_pzid: reference.payload });
    expect(resolved.status).toBe("ok");
    expect(checkNamed(resolved, "release_tuple_matched")?.detail).toMatch(/^tuple=release-a\.c3-a /);
  });

  it("revocation names the rule tuple, and a mutated policy cannot approve a revoked one", () => {
    const result = attest(c3Case, policy, { gce_pzid: reference.payload });
    expect(checkNamed(result, "release_tuple_not_revoked")?.detail).toContain(`matched_tuple_digest=${releaseTupleDigest(c3A)}`);
    const mutated = structuredClone(policy);
    mutated.releasePolicyV3!.revokedTuples = [releaseTupleDigest(c3A)];
    expect(() => assertGatewayPlatformSecurityFloor(mutated)).toThrow(/revokes/);
    expect(attest(c3Case, mutated).reason).toBe("policy_security_floor");
    const hostile = structuredClone(policy);
    (hostile.releasePolicyV3!.tuples[0]!.mrOwnerRule as unknown as Record<string, unknown>).zones = "us-west1-a";
    for (const presented of [undefined, reference.payload]) {
      expect(() => attest(c3Case, hostile, { gce_pzid: presented })).not.toThrow();
      expect(attest(c3Case, hostile, { gce_pzid: presented }).reason).toBe("policy_security_floor");
    }
    const smuggled = structuredClone(policy);
    smuggled.releasePolicyV3!.tuples[0]!.mrOwner = reference.mrOwner;
    expect(attest(c3Case, smuggled).reason).toBe("policy_security_floor");
  });
});

describe("the zero rule never admits a nonzero MROWNER", () => {
  const c3Case = { ...caseA, evidence: { ...caseA.evidence, quote: c3QuoteA } };

  it("refuses a C3 quote under a zero-rule tuple, with or without a gce-pzid tuple elsewhere in the policy", () => {
    const zeroOnly = attest(c3Case, policyWith([tupleA]));
    expect(zeroOnly.status).toBe("failed");
    expect(failedRequired(zeroOnly)).toEqual(["owner_config_registers_zero", "release_tuple_matched"]);
    // A rule on ANOTHER image lets owner_config_registers_zero defer to the
    // tuple match, which still refuses: tupleA has the zero rule.
    const mixed = attest(c3Case, policyWith([tupleA, { ...tupleB, mrOwnerRule: RULE }]));
    expect(failedRequired(mixed)).toEqual(["release_tuple_matched"]);
    expect(checkNamed(mixed, "release_tuple_matched")?.detail).toMatch(/MROWNER is nonzero and no matching tuple has a gce-pzid rule/);
    expect(attest(c3Case, policyWith([tupleA, { ...tupleB, mrOwnerRule: RULE }]), { gce_pzid: reference.payload }).status).toBe("failed");
  });

  it("refuses even a rule-less tuple that pins the exact nonzero MROWNER", () => {
    const pinned = attest(c3Case, policyWith([{ ...tupleA, mrOwner: reference.mrOwner }]));
    expect(failedRequired(pinned)).toEqual(["owner_config_registers_zero", "release_tuple_matched"]);
    // With a rule elsewhere, the tuple match alone must refuse it.
    const beside = attest(c3Case, policyWith([{ ...tupleA, mrOwner: reference.mrOwner }, { ...tupleB, mrOwnerRule: RULE }]));
    expect(failedRequired(beside)).toEqual(["release_tuple_matched"]);
  });

  it("C4 (zero MROWNER) under a zero-rule tuple is unchanged: not-applicable", () => {
    for (const tuples of [[tupleA], [tupleA, { ...tupleB, mrOwnerRule: RULE }]]) {
      const result = attest(caseA, policyWith(tuples));
      expect(result.status).toBe("ok");
      expect(result.instanceIdentity).toBe("not-applicable");
      expect(result.gceInstance).toBeNull();
      expect(checkNamed(result, "release_tuple_matched")?.detail).toBe("tuple=release-a.fw1 policy_sequence=1");
      expect(checkNamed(result, "gce_instance_identity")).toBeUndefined();
    }
    expect(attest(caseB, policyWith([tupleB])).instanceIdentity).toBe("not-applicable");
  });
});
