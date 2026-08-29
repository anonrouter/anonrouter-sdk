import { describe, expect, it } from "vitest";
import { verifyRawEvidence } from "../src/index.js";

// v0.0.141 (matches the shipped pin) at the reviewed endpoint inference.tinfoil.sh.
const FP = "6d657b353726893ee7202d33efc7c849a62693049c646f9394a8c6e2a165ed9936c024c4200878927767317ba3cbca7a";
const NONCE = "ab".repeat(32);

function tinfoilDoc(over: Record<string, unknown> = {}) {
  return {
    securityVerified: true,
    enclaveHost: "inference.tinfoil.sh",
    selectedRouterEndpoint: "inference.tinfoil.sh",
    configRepo: "tinfoilsh/confidential-model-router",
    releaseTag: "v0.0.141",
    releaseDigest: "7dcf6bade47993752689e9574ae6fba39ebed0fa98427329fc184558488ad8f6",
    codeFingerprint: FP,
    enclaveFingerprint: FP,
    enclaveMeasurement: { tlsPublicKeyFingerprint: "198c3340b8b007efdb5aa9b2bff68eb6776c4710f0731121f195c65e6410c232" },
    tlsPublicKey: "test-tls-public-key",
    steps: {
      fetchDigest: { status: "success" },
      verifyCode: { status: "success" },
      verifyEnclave: { status: "success" },
      compareMeasurements: { status: "success" },
      verifyCertificate: { status: "success" }
    },
    ...over
  };
}

describe("Tinfoil verdict (real pin + reviewed endpoint)", () => {
  it("verifies the v0.0.141 release at the pinned inference.tinfoil.sh endpoint", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc(), { upstreamModel: "openai/gpt-oss-120b", nonce: NONCE });
    expect(v.verification_level).toBe("sdk-verified");
    expect(v.status).toBe("ok");
    expect(v.checks.find((c) => c.name === "enclave_host_binding")?.passed).toBe(true);
  });

  it("fails enclave_host_binding when the attested host is not the reviewed endpoint", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({ selectedRouterEndpoint: "evil.example.com" }), { upstreamModel: "openai/gpt-oss-120b", nonce: NONCE });
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("enclave_host_binding");
  });
});
