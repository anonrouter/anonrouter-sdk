// What a Tinfoil verification document does and does not establish.
//
// Most of this file is one mutation per required check, because a Tinfoil verdict
// is almost entirely delegated: Tinfoil's own verifier does the cryptography and
// hands us a document. The only thing that makes the delegation safe is that
// every field we rely on is checked against something the document cannot choose
// for itself. The clearest example is the serving TLS key, which used to be
// "verified" by comparing two copies of ONE AMD-report field to each other. That
// comparison passes for every document in existence, including a forged one, so
// the tests for it are written as mutations of a document that otherwise passes.

import { describe, expect, it } from "vitest";
import { pinnedEndpointIdentityFor, verifyRawEvidence, TINFOIL_ENDPOINT_IDENTITY } from "../src/index.js";

// A signed Tinfoil release at the supported endpoint and GitHub authority.
const FP = "6d".repeat(48);
const TLS_FP = "19".repeat(32);
const NONCE = "ab".repeat(32);
const MODEL = { upstreamModel: "openai/gpt-oss-120b", nonce: NONCE };

/** The binding AnonRouter's worker (or `verifyTinfoilEnclave()`) records after a
 *  real pinned connection. Never something the document asserts about itself. */
function observedBinding(over: Record<string, unknown> = {}) {
  return {
    mode: "tls-pinned",
    endpointIdentity: "inference.tinfoil.sh",
    observedTlsSpki: TLS_FP,
    verified: true,
    ...over
  };
}

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
    transportBinding: observedBinding(),
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
    const v = verifyRawEvidence("tinfoil", tinfoilDoc(), MODEL);
    expect(v.verification_level).toBe("sdk-verified");
    expect(v.status).toBe("ok");
    expect(v.checks.find((c) => c.name === "enclave_host_binding")?.passed).toBe(true);
    expect(v.checks.find((c) => c.name === "attested_key_binding")?.passed).toBe(true);
  });

  it("reports AMD SEV-SNP and nothing about a GPU or the weights", () => {
    // The installed official verifier establishes no NVIDIA confidential-compute
    // evidence, and the document carries no model-weight digest. Reporting either
    // would be claiming a chain nobody walked.
    const v = verifyRawEvidence("tinfoil", tinfoilDoc(), MODEL);
    expect(v.hardware_type).toBe("amd-sev-snp");
    expect(v.model_weight_identity).toBeNull();
    expect(JSON.stringify(v)).not.toMatch(/nvidia/i);
  });

  it("accepts a later signed release without changing the package policy", () => {
    const next = "cd".repeat(48);
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      releaseTag: "v9.9.9",
      releaseDigest: "ef".repeat(32),
      codeFingerprint: next,
      enclaveFingerprint: next
    }), MODEL);
    expect(v.status).toBe("ok");
    expect(v.verification_level).toBe("sdk-verified");
  });

  it("rejects a document bound to another GitHub repository", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      configRepo: "attacker/confidential-model-router"
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("provider_release_authority");
  });
});

describe("the serving TLS key is bound to an observed connection, not to itself", () => {
  it("REFUSES a document that only repeats the attested key in two fields", () => {
    // The exact shape the old check accepted. Both fields are copies of one AMD
    // report field, so they agree in every document ever produced, including one
    // fabricated whole. With no observation of a real connection there is no
    // evidence about what is actually serving.
    const { transportBinding: _dropped, ...noObservation } = tinfoilDoc();
    expect(noObservation.tlsPublicKey).toBe(noObservation.enclaveMeasurement.tlsPublicKeyFingerprint);

    const v = verifyRawEvidence("tinfoil", noObservation, MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("attested_key_binding");
    // Pinned verbatim: the Python twin prints the same sentence, and a CLI that
    // explained the same refusal two different ways would be its own bug.
    expect(v.checks.find((c) => c.name === "attested_key_binding")?.detail)
      .toBe("attested TLS key is missing, or was not confirmed by an observed pinned connection to the enclave");
  });

  it("refuses a connection that served a different key than the report attested", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      transportBinding: observedBinding({ observedTlsSpki: "7e".repeat(32) })
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("attested_key_binding");
  });

  it("refuses an observation that did not verify", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      transportBinding: observedBinding({ verified: false })
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("attested_key_binding");
  });

  it("refuses an observation recorded against a different endpoint", () => {
    // A pinned connection to somewhere else says nothing about this enclave,
    // even when the key it saw happens to match.
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      transportBinding: observedBinding({ endpointIdentity: "inference.attacker.example" })
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("attested_key_binding");
  });

  it("refuses a transport mode other than tls-pinned", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      transportBinding: observedBinding({ mode: "tls" })
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("attested_key_binding");
  });

  it("refuses a malformed attested key even when the observation echoes it", () => {
    // Echoing back whatever the document said is the failure mode a binding is
    // supposed to rule out; the attested value still has to be a real SPKI hash.
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      enclaveMeasurement: { tlsPublicKeyFingerprint: "not-a-fingerprint" },
      transportBinding: observedBinding({ observedTlsSpki: "not-a-fingerprint" })
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("attested_key_binding");
  });
});

describe("both endpoint identities are fixed to inference.tinfoil.sh", () => {
  it("keeps the fixed host and the shipped pin from drifting apart", () => {
    // The verifier compares against a constant, on purpose. If the shipped
    // policy ever named a different host, every Tinfoil route would fail closed
    // with no obvious cause. Make that a build failure instead of a mystery.
    expect(TINFOIL_ENDPOINT_IDENTITY).toBe("inference.tinfoil.sh");
    expect(pinnedEndpointIdentityFor("tinfoil", "openai/gpt-oss-120b"))
      .toBe(TINFOIL_ENDPOINT_IDENTITY);
  });

  it("fails enclave_host_binding when the selected router is not the reviewed endpoint", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({ selectedRouterEndpoint: "evil.example.com" }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("enclave_host_binding");
  });

  it("fails enclave_host_binding when the ENCLAVE host is substituted", () => {
    // The document carries two endpoint identities. Checking only the selected
    // router left this one free to name anywhere at all.
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({ enclaveHost: "evil.example.com" }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("enclave_host_binding");
  });

  it("does not let the CALLER move the endpoint the document is graded against", () => {
    // Grading the document against an endpoint the caller supplied would make
    // the check a tautology from the other direction: name the attacker's host
    // in both places and it agrees with itself. The supported host is fixed.
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      enclaveHost: "evil.example.com",
      selectedRouterEndpoint: "https://evil.example.com",
      transportBinding: observedBinding({ endpointIdentity: "evil.example.com" })
    }), { ...MODEL, endpointIdentity: "evil.example.com" });
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("enclave_host_binding");
  });
});

describe("the rest of the required checks each fail on their own", () => {
  it("refuses a document that is not from the official verifier", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      verifier: { name: "lookalike-verifier", version: "1.2.1" }
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("official_verifier_identity");
  });

  it("refuses a live enclave that is not running the signed release", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({ enclaveFingerprint: "a1".repeat(48) }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("code_matches_live_enclave");
  });

  it("refuses a malformed signed release identity", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({ releaseDigest: "short" }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("signed_release_identity");
  });

  it("refuses a document whose own verifier did not confirm security", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({ securityVerified: false }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("sdk_security_verified");
  });

  it("refuses an incomplete set of verifier steps", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc({
      steps: { fetchDigest: { status: "success" } }
    }), MODEL);
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("sdk_verification_steps");
  });

  it("refuses the E2EE contract, which this route does not implement", () => {
    const v = verifyRawEvidence("tinfoil", tinfoilDoc(), { ...MODEL, privacyModality: "e2ee" });
    expect(v.status).toBe("failed");
    expect(v.reason).toBe("serving_modality_supported");
  });
});
