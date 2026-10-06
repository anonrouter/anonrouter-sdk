import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { verifyRawEvidence } from "../src/verify/index.js";
import { otherTransport, nearTransport, encryptField } from "../src/transport/near.js";
import { hexToBytes } from "../src/bytes.js";
import { pinnedMeasurementPolicyFor } from "../src/measurements.js";

const fixture = JSON.parse(readFileSync(new URL("../../../shared/vectors/near-authority.json", import.meta.url), "utf8"));
function verdict(evidence = structuredClone(fixture.evidence), model = fixture.upstreamModel) {
  return verifyRawEvidence("other", evidence, { upstreamModel: model, nonce: fixture.nonce,
    privacyModality: "e2ee", now: fixture.now });
}

describe("current direct provider identity and release authority", () => {
  it("accepts the retained public report at its capture time with an honest ceiling", () => {
    const r = verdict();
    expect(r.status).toBe("ok");
    expect(r.verification_level).toBe("provider-attested");
  });
  const mutations: Array<[string, (d: any) => void]> = [
    ["missing collateral", d => { delete d.anonrouter_release_collateral; }],
    ["wrong repository", d => { d.anonrouter_release_collateral.github[0].repository = "attacker/repo"; }],
    ["unpublished commit", d => { d.anonrouter_release_collateral.github[0].tags = {}; d.anonrouter_release_collateral.github[0].defaultBranchAncestors = []; }],
    ["tampered runtime file", d => { d.anonrouter_release_collateral.github[0].files[0].sha256 = "00".repeat(32); }],
    ["wrong published image", d => { d.anonrouter_release_collateral.dstackImages[0].measurements[0].rtmr2 = "11".repeat(48); }],
    ["unregistered compose", d => { d.anonrouter_release_collateral.onchain[0].composeHashAllowed = false; }],
    ["wrong KMS", d => { d.anonrouter_release_collateral.onchain[0].kms = "0x00"; }],
    ["wrong chain", d => { d.anonrouter_release_collateral.onchain[0].chainId = 1; }],
    ["stale publication", d => { d.anonrouter_release_collateral.github[0].fetchedAtMs -= 3 * 3600000; }],
    ["unreleased manager", d => { d.anonrouter_release_collateral.githubReleases[0].images = []; }],
    ["tampered manager log", d => { d.compose_manager_attestation.actions[0].image = "attacker/image"; }],
    ["malformed event log", d => { d.event_log = []; d.info.tcb_info.event_log = []; }],
    ["substituted encryption key", d => { d.signing_public_key = "11".repeat(32); }],
    ["wrong signing algorithm", d => { d.signing_algo = "ecdsa"; }],
    ["missing GPU", d => { delete d.nvidia_payload; }],
    ["GPU nonce substitution", d => { const g = JSON.parse(d.nvidia_payload); g.nonce = "00".repeat(32); d.nvidia_payload = JSON.stringify(g); }],
    ["malformed collateral", d => { d.anonrouter_release_collateral.github = {}; }],
  ];
  it.each(mutations)("refuses %s", (_name, mutate) => {
    const d = structuredClone(fixture.evidence); mutate(d);
    expect(verdict(d).status).toBe("failed");
  });
  it("refuses an unreviewed model even with otherwise genuine evidence", () => {
    expect(pinnedMeasurementPolicyFor("other", "unknown/model")).toBeUndefined();
    expect(verdict(undefined, "unknown/model").status).toBe("failed");
  });
  it("refuses a different caller nonce", () => {
    expect(verifyRawEvidence("other", fixture.evidence, { upstreamModel: fixture.upstreamModel,
      nonce: "ab".repeat(32), privacyModality: "e2ee", now: fixture.now }).status).toBe("failed");
  });
  it("preserves other in session, ticket body and protocol headers; decrypts the reply", async () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(fixture.now);
    let session;
    try {
      session = otherTransport.createSession({ upstreamModel: fixture.upstreamModel,
        nonce: fixture.nonce, rawEvidence: fixture.evidence, normalized: verdict() });
      expect(session.provider).toBe("other");
      const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) => {
        const headers = init!.headers as Record<string, string>;
        const body = JSON.parse(init!.body as string);
        expect(body.provider).toBe("other");
        expect(headers["x-anonrouter-e2ee-provider"]).toBe("other");
        expect(headers["x-encryption-version"]).toBe("2");
        expect(headers.authorization).toBeUndefined();
        expect(body.messages[0].content).not.toBe("canary");
        const ciphertext = encryptField("reply", hexToBytes(headers["x-client-pub-key"]!));
        return new Response(`data: ${JSON.stringify({ choices: [{ delta: { content: ciphertext } }] })}\n\ndata: [DONE]\n\n`);
      });
      const request = { model: fixture.upstreamModel, upstreamModel: fixture.upstreamModel,
        messages: [{ role: "user" as const, content: "canary" }], maxOutputTokens: 8 };
      const options = { ticket: "synthetic", http: { baseUrl: "https://test.invalid", fetchImpl } };
      await expect(nearTransport.complete(session, request, options)).rejects.toThrow();
      expect(fetchImpl).not.toHaveBeenCalled();
      expect((await otherTransport.complete(session, request, options)).content).toBe("reply");
    } finally { if (session) otherTransport.dispose(session); clock.mockRestore(); }
  });
  it("refuses a normalized encryption key disagreement before encryption", () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(fixture.now);
    try {
      expect(() => otherTransport.createSession({ upstreamModel: fixture.upstreamModel,
        nonce: fixture.nonce, rawEvidence: fixture.evidence,
        normalized: { ...verdict(), attested_encryption_key: "00".repeat(32) } })).toThrow(/disagrees/);
    } finally { clock.mockRestore(); }
  });
});
