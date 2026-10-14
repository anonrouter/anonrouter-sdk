// Owner-signed release policy v3 for GCP-native content nodes.
//
// Fixtures are deterministic: Ed25519 seeds 0x11*32 (custodian.prod.usb) and
// 0x22*32 (custodian.prod.laptop). The known answers below were computed with
// the server's canonical()/digest() (src/contentNodes/bootstrap/canonical.ts)
// and node:crypto Ed25519, an implementation independent of this SDK's, so a
// byte-level divergence in domains, canonical JSON or key order fails here.
// Every value is synthetic; nothing is a production key, pin or measurement.

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it, vi } from "vitest";
import vectors from "../../../shared/vectors/gateway-release-tuples.json" with { type: "json" };
import { bytesToHex } from "../src/bytes.js";
import { createClient } from "../src/client.js";
import { packagedReleasePolicyV3Authority } from "../src/gateway/release-v3.js";
import { ConfidentialError } from "../src/errors.js";
import { packagedGatewayPolicyAuthority, verifySignedGatewayPolicy, type GatewayPolicyStateStore } from "../src/gateway/authority.js";
import { assertGatewayPlatformSecurityFloor, loadGatewayPolicy, type GatewayMeasurementPolicy } from "../src/gateway/policy.js";
import {
  createReleasePolicyV3Source, releaseEnvelopeV3Message, releaseOwnerRootSha256, releasePolicyV3GatewayPolicy,
  releaseTupleDigest, ReleasePolicyV3Error, verifyReleaseEnvelopeV3, verifyReleasePolicyV3,
  MAX_RELEASE_V3_OFFLINE_MS, type ReleasePolicyV3Checkpoint, type ReleasePolicyV3Trust, type ReleaseV3Role
} from "../src/gateway/release-v3.js";
import { createFileGatewayPolicyStateStore } from "../src/gateway/state-node.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";

const USB_SEED = new Uint8Array(32).fill(0x11);
const LAPTOP_SEED = new Uint8Array(32).fill(0x22);
const OTHER_SEED = new Uint8Array(32).fill(0x33);
const DEPLOYMENT_ID = "gcp-content-qualification";
const GROUP_ID = "release-owner-qualification";
const ORIGIN = "https://content.gcp.example";
const FEED = "https://policy.gcp.example/.well-known/anonrouter/release-policy-v3.json";
const NOW = vectors.verifyCases[0]!.expectations.nowMs;

// Server-side known answers (see the header).
const KAT = {
  usbPublicKey: "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
  laptopPublicKey: "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
  ownerRootSha256: "dbf88bb4116a138225f60dc7c28506e9b4072f02e708795d0e2100eb09bad503",
  tupleDigestA: "d6f9cd37055026550b9c9f1042217f04e6c625c0448102bb935826dd99987859",
  tupleDigestB: "2a78ed89d8c23760afd73ad736ca12c95c8315d231c3094ac39c08c6563e6256",
  message1: "ee7e5f365db23a53049197de76bfc3f02fe71564ebc9622c3b85901a18721481",
  message2: "f759100869a393e22a1733edf5525f2765175df4478261e2e975412ae8d42363",
  policySha1: "c6a77ea9c497787e40ca5df26a599dfaaa9728794e14db7bc46f07621e34ec97",
  policySha2: "73ccddabad0b141e07a7e143e1b28c6568bc746f988f87e6c815189e25c4b4f3",
  signatures1: [
    "9ab195e96a302f3e439538afea0ff6d5abdc6b8f009a5747d37d8a5354f4f6d611db4fc23abce77e27cbc9f301ce186559bf1e5d1f1ce254827277be2a56170d",
    "554642198de17f82d8e0c72448ac0a3e9cc6d84ce7a6c5747d4f971e654de2b24ef490bb6a42fda741454ac3929bc35aa442df631fe009297a5dfaa60e2e4800"
  ],
  signatures2: [
    "d929110b92cfb947e77587a2108ab6bf15bdba007f3e440a5f9f1114db028f151a3c11d99ec97403e5e838c85cb02b65b32612090570c22bdc7551d246a63103",
    "8114b6ca5681f461cb5d36cc5b978605be209c044ec59ae23f949331941d247ffe754c0aef1b05ff1cc5f261f578a2d9c9039f5b8e1b58b70966534c32f9dd08"
  ]
};

const keys = [
  { keyId: "custodian.prod.usb" as const, publicKey: bytesToHex(ed25519.getPublicKey(USB_SEED)) },
  { keyId: "custodian.prod.laptop" as const, publicKey: bytesToHex(ed25519.getPublicKey(LAPTOP_SEED)) }
];
const trust: ReleasePolicyV3Trust = {
  deploymentId: DEPLOYMENT_ID, groupId: GROUP_ID, keys,
  ownerRootSha256: releaseOwnerRootSha256({ deploymentId: DEPLOYMENT_ID, groupId: GROUP_ID, keys }),
  minimumPolicySequence: 1
};

const ZERO = "00".repeat(48);
// Tuple A and B are exactly the registers of the first two shared GCP quotes.
const tupleA = { tupleId: "release-a.fw1", mrTd: "1a".repeat(48), mrConfigId: ZERO, mrOwner: ZERO, mrOwnerConfig: ZERO,
  rtmr0: "2b".repeat(48), rtmr1: "3c".repeat(48), rtmr2: "4d".repeat(48), rtmr3: ZERO,
  tdAttributes: "0000001000000000", xfam: "e718060000000000" };
const tupleB = { ...tupleA, tupleId: "release-b.fw2", mrTd: "5e".repeat(48), rtmr0: "6f".repeat(48) };
const basePayload = { protocol: "anonrouter-content-node-bootstrap-v1", kind: "content-node-release-policy",
  deploymentId: DEPLOYMENT_ID, revokedGenerations: [] as string[], minimumGenerationRevision: 1,
  maxEvidenceAgeMs: 300000, tcbStatus: "UpToDate" };
const payload1 = { ...basePayload, sequence: 1, issuedAtMs: 1791240600000, tuples: [tupleA, tupleB], revokedTuples: [] as string[] };
const payload2 = { ...basePayload, sequence: 2, issuedAtMs: 1791327000000, tuples: [tupleB], revokedTuples: [KAT.tupleDigestA] };

function sign(payload: unknown, options: { role?: ReleaseV3Role; seeds?: Uint8Array[]; keyIds?: string[]; groupId?: string;
  ownerRootSha256?: string } = {}) {
  const role = options.role ?? "release-policy";
  const groupId = options.groupId ?? GROUP_ID;
  const ownerRootSha256 = options.ownerRootSha256 ?? trust.ownerRootSha256;
  const message = releaseEnvelopeV3Message(role, groupId, ownerRootSha256, payload);
  const seeds = options.seeds ?? [USB_SEED, LAPTOP_SEED];
  const keyIds = options.keyIds ?? ["custodian.prod.usb", "custodian.prod.laptop"];
  return { protocol: "anonrouter-content-release-envelope-v3", role, groupId, ownerRootSha256, payload,
    signatures: seeds.map((seed, index) => ({ keyId: keyIds[index]!, signature: bytesToHex(ed25519.sign(message, seed)) })) };
}
const envelope1 = sign(payload1);
const envelope2 = sign(payload2);

function refusal(run: () => unknown): string {
  try { run(); } catch (error) {
    if (error instanceof ReleasePolicyV3Error) return error.code;
    throw error;
  }
  throw new Error("expected a refusal");
}
const checkpointOf = (v: { sequence: number; policySha256: string; revokedTuples: string[] }): ReleasePolicyV3Checkpoint =>
  ({ sequence: v.sequence, policySha256: v.policySha256, revokedTuples: v.revokedTuples });

describe("byte compatibility with the server encoding", () => {
  it("derives the server's keys, owner root, tuple digests, messages and signatures", () => {
    expect(keys.map((key) => key.publicKey)).toEqual([KAT.usbPublicKey, KAT.laptopPublicKey]);
    expect(trust.ownerRootSha256).toBe(KAT.ownerRootSha256);
    expect(releaseTupleDigest(tupleA)).toBe(KAT.tupleDigestA);
    expect(releaseTupleDigest(tupleB)).toBe(KAT.tupleDigestB);
    expect(bytesToHex(releaseEnvelopeV3Message("release-policy", GROUP_ID, KAT.ownerRootSha256, payload1))).toBe(KAT.message1);
    expect(bytesToHex(releaseEnvelopeV3Message("release-policy", GROUP_ID, KAT.ownerRootSha256, payload2))).toBe(KAT.message2);
    expect(envelope1.signatures.map((s) => s.signature)).toEqual(KAT.signatures1);
    expect(envelope2.signatures.map((s) => s.signature)).toEqual(KAT.signatures2);
  });

  it("the role is part of the signed domain", () => {
    expect(bytesToHex(releaseEnvelopeV3Message("generation", GROUP_ID, KAT.ownerRootSha256, payload1))).not.toBe(KAT.message1);
  });

  it("a tuple label is not part of its digest", () => {
    expect(releaseTupleDigest({ ...tupleA, tupleId: "renamed" })).toBe(KAT.tupleDigestA);
  });
});

describe("release policy v3 envelope", () => {
  it("accepts both owner signatures over a policy with no expiry", () => {
    const verified = verifyReleasePolicyV3(envelope1, trust);
    expect(verified.sequence).toBe(1);
    expect(verified.policySha256).toBe(KAT.policySha1);
    expect(verified.tuples.map((t) => t.tupleDigest)).toEqual([KAT.tupleDigestA, KAT.tupleDigestB]);
    expect(verifyReleasePolicyV3(envelope2, trust).policySha256).toBe(KAT.policySha2);
  });

  it("refuses a single signature, swapped order, a wrong signer and a tampered payload", () => {
    expect(refusal(() => verifyReleasePolicyV3({ ...envelope1, signatures: [envelope1.signatures[0]] }, trust))).toBe("signature_invalid");
    expect(refusal(() => verifyReleasePolicyV3({ ...envelope1, signatures: [...envelope1.signatures].reverse() }, trust))).toBe("signature_invalid");
    expect(refusal(() => verifyReleasePolicyV3(sign(payload1, { seeds: [USB_SEED, USB_SEED] }), trust))).toBe("signature_invalid");
    expect(refusal(() => verifyReleasePolicyV3(sign(payload1, { seeds: [OTHER_SEED, LAPTOP_SEED] }), trust))).toBe("signature_invalid");
    expect(refusal(() => verifyReleasePolicyV3(sign(payload1, { seeds: [LAPTOP_SEED, USB_SEED] }), trust))).toBe("signature_invalid");
    expect(refusal(() => verifyReleasePolicyV3({ ...envelope1, signatures: [...envelope1.signatures, envelope1.signatures[1]] }, trust))).toBe("signature_invalid");
    expect(refusal(() => verifyReleasePolicyV3({ ...envelope1, payload: { ...payload1, sequence: 9 } }, trust))).toBe("signature_invalid");
    const upper = { ...envelope1, signatures: envelope1.signatures.map((s) => ({ ...s, signature: s.signature.toUpperCase() })) };
    expect(refusal(() => verifyReleasePolicyV3(upper, trust))).toBe("signature_invalid");
  });

  it("refuses another role, group or owner root", () => {
    expect(refusal(() => verifyReleasePolicyV3(sign(payload1, { role: "generation" }), trust))).toBe("wrong_role");
    expect(refusal(() => verifyReleaseEnvelopeV3(envelope1, trust, "generation"))).toBe("wrong_role");
    expect(refusal(() => verifyReleasePolicyV3(sign(payload1, { groupId: "another-group" }), trust))).toBe("wrong_group");
    expect(refusal(() => verifyReleasePolicyV3(sign(payload1, { ownerRootSha256: "ab".repeat(32) }), trust))).toBe("wrong_owner_root");
  });

  it("pins the owner root: keys, group or deployment that do not hash to it refuse", () => {
    expect(refusal(() => verifyReleasePolicyV3(envelope1, { ...trust, ownerRootSha256: "ab".repeat(32) }))).toBe("wrong_owner_root");
    expect(refusal(() => verifyReleasePolicyV3(envelope1, { ...trust, groupId: "release-owner-other" }))).toBe("wrong_owner_root");
    const otherKey = { keyId: "custodian.prod.laptop" as const, publicKey: bytesToHex(ed25519.getPublicKey(OTHER_SEED)) };
    expect(refusal(() => verifyReleasePolicyV3(envelope1, { ...trust, keys: [keys[0]!, otherKey] }))).toBe("wrong_owner_root");
    const sameKey = [keys[0]!, { keyId: "custodian.prod.laptop" as const, publicKey: keys[0]!.publicKey }];
    expect(refusal(() => verifyReleasePolicyV3(envelope1, { ...trust, keys: sameKey,
      ownerRootSha256: releaseOwnerRootSha256({ deploymentId: DEPLOYMENT_ID, groupId: GROUP_ID, keys: sameKey }) }))).toBe("trust_invalid");
    expect(refusal(() => verifyReleasePolicyV3(envelope1, { ...trust, keys: [...keys].reverse() }))).toBe("trust_invalid");
  });

  it("never accepts a v1 or v2 envelope, and the v1 verifier never accepts v3", () => {
    const v2 = { protocol: "anonrouter-content-owner-quorum-v2", role: "release-policy", groupId: GROUP_ID,
      anchorsSha256: trust.ownerRootSha256, payload: payload1, signatures: envelope1.signatures };
    expect(refusal(() => verifyReleasePolicyV3(v2, trust))).toBe("contract_invalid");
    expect(refusal(() => verifyReleasePolicyV3({ ...envelope1, protocol: "anonrouter-content-release-envelope-v2" }, trust))).toBe("contract_invalid");
    expect(refusal(() => verifyReleasePolicyV3({ schema: "anonrouter.gateway-policy-envelope/v1", payload: "{}", signatures: [] }, trust))).toBe("contract_invalid");
    expect(() => verifySignedGatewayPolicy(envelope1, packagedGatewayPolicyAuthority(), ORIGIN, NOW)).toThrow(/fields/);
  });

  it("refuses malformed or out-of-contract payloads, each correctly signed", () => {
    const signed = (payload: unknown) => refusal(() => verifyReleasePolicyV3(sign(payload), trust));
    expect(signed({ ...payload1, expiresAtMs: 1791413400000 })).toBe("contract_invalid");
    expect(signed({ ...payload1, deploymentId: "gcp-content-production" })).toBe("wrong_deployment");
    expect(signed({ ...payload1, kind: "content-node-policy" })).toBe("contract_invalid");
    expect(signed({ ...payload1, sequence: 0 })).toBe("contract_invalid");
    expect(signed({ ...payload1, tuples: [] })).toBe("contract_invalid");
    expect(signed({ ...payload1, tuples: [tupleA, { ...tupleB, tupleId: tupleA.tupleId }] })).toBe("contract_invalid");
    expect(signed({ ...payload1, tuples: [{ ...tupleA, rtmr1: "3C".repeat(48) }] })).toBe("contract_invalid");
    expect(signed({ ...payload1, tuples: [{ ...tupleA, notBeforeMs: 0 }] })).toBe("contract_invalid");
    expect(signed({ ...payload1, tuples: Array.from({ length: 17 }, (_, i) => ({ ...tupleA, tupleId: `t${i}` })) })).toBe("contract_invalid");
    expect(signed({ ...payload1, revokedTuples: [KAT.tupleDigestB, KAT.tupleDigestA].sort().reverse() })).toBe("contract_invalid");
    expect(signed({ ...payload1, revokedTuples: ["01".repeat(32), "01".repeat(32)] })).toBe("contract_invalid");
    expect(signed({ ...payload1, maxEvidenceAgeMs: 300001 })).toBe("contract_invalid");
    expect(signed({ ...payload1, tcbStatus: "SWHardeningNeeded" })).toBe("contract_invalid");
    // A float or negative number has no canonical encoding, so it cannot be signed.
    expect(refusal(() => sign({ ...payload1, issuedAtMs: 1.5 }))).toBe("contract_invalid");
  });

  it("refuses a policy that approves a tuple it also revokes", () => {
    expect(refusal(() => verifyReleasePolicyV3(sign({ ...payload1, revokedTuples: [KAT.tupleDigestA] }), trust)))
      .toBe("revoked_tuple_approved");
  });
});

describe("monotonic checkpoint", () => {
  const held1 = checkpointOf(verifyReleasePolicyV3(envelope1, trust));
  const held2 = checkpointOf(verifyReleasePolicyV3(envelope2, trust, held1));

  it("accepts a higher sequence that keeps every revocation, and the same policy again", () => {
    expect(held2.sequence).toBe(2);
    expect(verifyReleasePolicyV3(envelope2, trust, held2).sequence).toBe(2);
  });

  it("refuses a lower sequence than the held one or the pinned minimum", () => {
    expect(refusal(() => verifyReleasePolicyV3(envelope1, trust, held2))).toBe("policy_rollback");
    expect(refusal(() => verifyReleasePolicyV3(envelope1, { ...trust, minimumPolicySequence: 2 }))).toBe("policy_rollback");
  });

  it("refuses a different policy at the held sequence", () => {
    const fork = sign({ ...payload2, issuedAtMs: payload2.issuedAtMs + 1 });
    expect(refusal(() => verifyReleasePolicyV3(fork, trust, held2))).toBe("policy_fork");
  });

  it("refuses a successor that drops a held revocation", () => {
    const reversed = sign({ ...payload2, sequence: 3, tuples: [tupleA, tupleB], revokedTuples: [] });
    expect(refusal(() => verifyReleasePolicyV3(reversed, trust, held2))).toBe("revocation_reversed");
    const kept = sign({ ...payload2, sequence: 3, revokedTuples: [KAT.tupleDigestA, "ff".repeat(32)] });
    expect(verifyReleasePolicyV3(kept, trust, held2).sequence).toBe(3);
  });
});

type VerifyCase = (typeof vectors.verifyCases)[number];
function attest(testCase: VerifyCase, policy: GatewayMeasurementPolicy) {
  const e = testCase.expectations;
  return verifyGatewayAttestation(testCase.evidence as unknown as GatewayAttestationEvidence, {
    nonce: e.nonce, origin: e.origin, policy, now: e.nowMs, observedTlsSpkiSha256: e.observedTlsSpki.value,
    observedOnRetainedConnection: true, unqualifiedPlatformPilot: true,
    chainVerifier: { implementation: "vector-stub", verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" }) }
  });
}
const quoteA = vectors.verifyCases[0]!;
const quoteB = vectors.verifyCases[1]!;
const failedRequired = (result: ReturnType<typeof attest>) => result.checks.filter((c) => c.required && !c.passed).map((c) => c.name);

describe("connection-bound quote against the release policy", () => {
  const policy1 = releasePolicyV3GatewayPolicy(verifyReleasePolicyV3(envelope1, trust), [ORIGIN]);
  const policy2 = releasePolicyV3GatewayPolicy(verifyReleasePolicyV3(envelope2, trust), [ORIGIN]);

  it("derives a gcp-tdx-native policy that holds the full security floor", () => {
    expect(policy1.platformKind).toBe("gcp-tdx-native");
    expect(policy1.releaseTuples).toBeUndefined();
    expect(() => assertGatewayPlatformSecurityFloor(policy1)).not.toThrow();
    expect(policy1.acceptableTcbStatuses).toEqual(["UpToDate"]);
  });

  it("accepts a quote whose registers are an approved tuple, with no expiry", () => {
    const result = attest(quoteA, policy1);
    expect(failedRequired(result)).toEqual([]);
    expect(result.status).toBe("ok");
    expect(result.verificationLevel).toBe("hardware-verified");
    expect(result.checks.find((c) => c.name === "release_tuple_matched")?.detail).toBe("tuple=release-a.fw1 policy_sequence=1");
    // The release policy pins registers, not the binding's identity claims.
    expect(result.checks.some((c) => ["app_id_pinned", "compose_hash_pinned", "release_pinned"].includes(c.name))).toBe(false);
    expect(attest(quoteB, policy1).status).toBe("ok");
  });

  it("refuses a revoked tuple and an unapproved one", () => {
    const revoked = attest(quoteA, policy2);
    expect(revoked.status).toBe("failed");
    expect(revoked.reason).toBe("release_tuple_not_revoked");
    expect(failedRequired(revoked)).toEqual(["release_tuple_not_revoked", "release_tuple_matched"]);
    expect(attest(quoteB, policy2).status).toBe("ok");
    const onlyB = releasePolicyV3GatewayPolicy(verifyReleasePolicyV3(sign({ ...payload1, tuples: [tupleB] }), trust), [ORIGIN]);
    const unapproved = attest(quoteA, onlyB);
    expect(unapproved.reason).toBe("release_tuple_matched");
  });

  it("re-checks the floor so a mutated policy cannot approve a revoked tuple or mix forms", () => {
    const mutated = structuredClone(policy2);
    mutated.releasePolicyV3!.tuples.push({ ...tupleA });
    expect(() => assertGatewayPlatformSecurityFloor(mutated)).toThrow(/revokes/);
    expect(attest(quoteA, mutated).reason).toBe("policy_security_floor");
    const mixed = { ...structuredClone(policy1), releaseTuples: loadGatewayPolicy(quoteA.policy).releaseTuples };
    expect(() => assertGatewayPlatformSecurityFloor(mixed)).toThrow(/cannot also carry release tuples/);
    const widened = { ...structuredClone(policy1), appIds: ["5a".repeat(32)] };
    expect(() => assertGatewayPlatformSecurityFloor(widened)).toThrow(/identity lists must be empty/);
    const weakened = { ...structuredClone(policy1), requireHardwareVerified: false };
    expect(attest(quoteA, weakened).reason).toBe("policy_security_floor");
    const { platformKind: _kind, ...legacy } = structuredClone(policy1);
    expect(() => assertGatewayPlatformSecurityFloor(legacy as GatewayMeasurementPolicy)).toThrow(/gcp-tdx-native/);
  });

  it("a policy document cannot carry release policy v3 facts into the loader", () => {
    expect(() => loadGatewayPolicy({ ...quoteA.policy, releasePolicyV3: policy1.releasePolicyV3 })).toThrow(/unknown field/);
  });
});

function feed(answers: Array<unknown | Error | number>) {
  let index = 0;
  const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
    expect(init?.credentials).toBe("omit");
    expect(init?.redirect).toBe("error");
    expect(new Headers(init?.headers).has("authorization")).toBe(false);
    const answer = answers[Math.min(index++, answers.length - 1)];
    if (answer instanceof Error) throw answer;
    if (typeof answer === "number") return new Response("{}", { status: answer });
    return Response.json(answer);
  });
  return fetchMock;
}
function memoryStore(): GatewayPolicyStateStore & { seen: unknown[] } {
  const seen: unknown[] = [];
  return { seen, async observe(authority, checkpoint) { seen.push({ authority, ...checkpoint }); } };
}

describe("policy feed, offline window and durable checkpoint", () => {
  it("checks the feed on every resolve by default and adopts a higher sequence", async () => {
    const fetchMock = feed([envelope1, envelope2]);
    const store = memoryStore();
    const source = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN], fetch: fetchMock as typeof fetch,
      now: () => NOW, stateStore: store });
    const first = await source.resolve(ORIGIN);
    expect(first.format).toBe("release-policy-v3");
    expect(first.sequence).toBe(1);
    expect(first.expiresAtMs).toBe(NOW + MAX_RELEASE_V3_OFFLINE_MS);
    const second = await source.resolve(ORIGIN);
    expect(second.sequence).toBe(2);
    expect(second.policy.releasePolicyV3!.revokedTuples).toEqual([KAT.tupleDigestA]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(store.seen).toEqual([
      { authority: `anonrouter.release-policy-v3/${KAT.ownerRootSha256}`, sequence: 1, payloadSha256: KAT.policySha1 },
      { authority: `anonrouter.release-policy-v3/${KAT.ownerRootSha256}`, sequence: 2, payloadSha256: KAT.policySha2 }
    ]);
  });

  it("uses the last verified policy for under one hour when the feed is unreachable, then refuses", async () => {
    let time = NOW;
    const fetchMock = feed([envelope1, new TypeError("network down"), 503]);
    const source = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN], fetch: fetchMock as typeof fetch,
      now: () => time, stateStore: memoryStore() });
    await source.resolve(ORIGIN);
    time = NOW + 30 * 60_000;
    expect((await source.resolve(ORIGIN)).confirmedAtMs).toBe(NOW);
    time = NOW + MAX_RELEASE_V3_OFFLINE_MS - 1;
    expect((await source.resolve(ORIGIN)).sequence).toBe(1);
    time = NOW + MAX_RELEASE_V3_OFFLINE_MS;
    await expect(source.resolve(ORIGIN)).rejects.toMatchObject({ code: "cache_stale" });
  });

  it("refuses with nothing cached, on a 4xx, and on a bad, rolled-back or forked answer without using the cache", async () => {
    const empty = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN],
      fetch: feed([new TypeError("down")]) as typeof fetch, now: () => NOW, stateStore: memoryStore() });
    await expect(empty.resolve(ORIGIN)).rejects.toMatchObject({ code: "feed_unavailable" });
    const tampered = { ...envelope2, payload: { ...payload2, revokedTuples: [] } };
    const fork = sign({ ...payload2, issuedAtMs: payload2.issuedAtMs + 1 });
    for (const [answer, code] of [[404, "feed_unavailable"], [tampered, "signature_invalid"], [envelope1, "policy_rollback"], [fork, "policy_fork"]] as const) {
      const source = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN],
        fetch: feed([envelope2, answer]) as typeof fetch, now: () => NOW, stateStore: memoryStore() });
      await source.resolve(ORIGIN);
      await expect(source.resolve(ORIGIN)).rejects.toMatchObject({ code });
    }
  });

  it("refuses an unauthorized origin and a feed hosted on a gateway origin", async () => {
    const source = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN],
      fetch: feed([envelope1]) as typeof fetch, now: () => NOW, stateStore: memoryStore() });
    await expect(source.resolve("https://other.gcp.example")).rejects.toMatchObject({ code: "unauthorized_origin" });
    expect(() => createReleasePolicyV3Source({ trust, url: `${ORIGIN}/policy.json`, origins: [ORIGIN] })).toThrow(/separate/);
    expect(() => createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN], maxOfflineMs: MAX_RELEASE_V3_OFFLINE_MS + 1 })).toThrow(ReleasePolicyV3Error);
  });

  it("a failed durable write refuses the policy", async () => {
    const source = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN], fetch: feed([envelope1]) as typeof fetch,
      now: () => NOW, stateStore: { observe: async () => { throw new Error("disk full"); } } });
    await expect(source.resolve(ORIGIN)).rejects.toThrow(/disk full/);
  });

  it("the durable checkpoint refuses rollback and fork across restarts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "anonrouter-release-v3-"));
    try {
      const fresh = (answer: unknown) => createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN],
        fetch: feed([answer]) as typeof fetch, now: () => NOW, stateStore: createFileGatewayPolicyStateStore(directory) });
      expect((await fresh(envelope2).resolve(ORIGIN)).sequence).toBe(2);
      await expect(fresh(envelope1).resolve(ORIGIN)).rejects.toThrow(/rollback/);
      await expect(fresh(sign({ ...payload2, issuedAtMs: payload2.issuedAtMs + 1 })).resolve(ORIGIN)).rejects.toThrow(/conflicting/);
      expect((await fresh(envelope2).resolve(ORIGIN)).sequence).toBe(2);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("client wiring", () => {
  it("packages owner keys and a sequence floor, without node image measurements", () => {
    const root = packagedReleasePolicyV3Authority();
    expect(releaseOwnerRootSha256(root.trust)).toBe(root.trust.ownerRootSha256);
    expect(root.trust.minimumPolicySequence).toBe(6);
    expect(root.origins).toEqual(["https://api.anonrouter.ai"]);
    expect(Object.keys(root.trust).sort()).toEqual(["deploymentId", "groupId", "keys", "minimumPolicySequence", "ownerRootSha256"]);
    root.trust.keys[0]!.publicKey = "00".repeat(32);
    expect(packagedReleasePolicyV3Authority().trust.keys[0]!.publicKey).not.toBe(root.trust.keys[0]!.publicKey);
  });

  it("the production client selects the fixed release-v3 feed by default and refuses a test owner", async () => {
    const feedMock = feed([envelope1]);
    vi.stubGlobal("fetch", feedMock);
    try {
      const gatewayMock = vi.fn(async () => { throw new Error("no content request expected"); });
      const c = createClient({ apiKey: "synthetic-key", fetch: gatewayMock as unknown as typeof fetch });
      await expect(c.verifyGateway()).rejects.toThrow(/wrong_group|wrong_owner_root/);
      expect(feedMock).toHaveBeenCalledTimes(1);
      const [url, init] = feedMock.mock.calls[0]!;
      expect(url).toBe(packagedReleasePolicyV3Authority().url);
      expect(init).toMatchObject({ method: "GET", credentials: "omit", redirect: "error" });
      expect(JSON.stringify(init)).not.toContain("synthetic-key");
      expect(gatewayMock).not.toHaveBeenCalled();
    } finally { vi.unstubAllGlobals(); }
  });

  function client(pilot: boolean) {
    const feedMock = feed([envelope1]);
    const source = createReleasePolicyV3Source({ trust, url: FEED, origins: [ORIGIN], fetch: feedMock as typeof fetch,
      stateStore: memoryStore() });
    const gatewayMock = vi.fn(async () => { throw new Error("no gateway request may be made"); });
    const c = createClient({ inferenceBaseUrl: ORIGIN, controlBaseUrl: "https://control.gcp.example", apiKey: "synthetic-key",
      fetch: gatewayMock as unknown as typeof fetch, gatewayPolicyUpdates: source });
    return { verify: () => c.verifyGateway(pilot ? { unqualifiedPlatformPilot: true } : {}), feedMock, gatewayMock };
  }

  it("a qualified v3 approval needs connection binding with or without the old pilot flag", async () => {
    for (const [pilot, pattern] of [[false, /connection binding/], [true, /connection binding/]] as const) {
      const { verify, feedMock, gatewayMock } = client(pilot);
      const error = await verify().catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ConfidentialError);
      expect((error as ConfidentialError).code).toBe("unsupported_request");
      expect((error as Error).message).toMatch(pattern);
      expect(feedMock).toHaveBeenCalledTimes(1);
      expect(gatewayMock).not.toHaveBeenCalled();
    }
  });
});
