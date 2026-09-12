import { describe, expect, it } from "vitest";
import { verifyRawEvidence } from "../src/index.js";

// A signed Tinfoil release at the supported endpoint and GitHub authority.
const FP = "6d".repeat(48);
const TLS_FP = "19".repeat(32);
const NONCE = "ab".repeat(32);

function tinfoilDoc(over: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    securityVerified: true,
    enclaveHost: "inference.tinfoil.sh",
    selectedRouterEndpoint: "inference.tinfoil.sh",
    configRepo: "tinfoilsh/confidential-model-router",
    releaseTag: "v99.0.0",
    releaseDigest: "7d".repeat(32),
    codeFingerprint: FP,
    enclaveFingerprint: FP,
    enclaveMeasurement: { tlsPublicKeyFingerprint: TLS_FP },
    tlsPublicKey: TLS_FP,
    verifier: { name: "@tinfoilsh/verifier", version: "1.2.1" },
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

describe("Tinfoil verdict (provider authority + reviewed endpoint)", () => {
  it("verifies a signed release at inference.tinfoil.sh", () => {
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

  it("accepts a later signed release without changing the package policy", () => {
    const next = "cd".repeat(48);
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      releaseTag: "v9.9.9",
      releaseDigest: "ef".repeat(32),
      codeFingerprint: next,
      enclaveFingerprint: next
    }), { upstreamModel: "openai/gpt-oss-120b", nonce: NONCE });
    expect(v.status).toBe("ok");
    expect(v.verification_level).toBe("sdk-verified");
  });

  it("rejects a document bound to another GitHub repository", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      configRepo: "attacker/confidential-model-router"
    }), { upstreamModel: "openai/gpt-oss-120b", nonce: NONCE });
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("provider_release_authority");
  });
});
