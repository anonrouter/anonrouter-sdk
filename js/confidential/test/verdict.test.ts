// Verdict tests: valid Venice evidence verifies to status ok / level
// provider-attested (never hardware-verified), and a nonce that was not the one the
// evidence bound fails closed.

import { describe, expect, it } from "vitest";
import { randomBytes, bytesToHex } from "../src/bytes.js";
import { verifyRawEvidence } from "../src/index.js";
import { createVeniceMockEnclave } from "./helpers/mock-enclaves.js";

const MODEL = "venice-uncensored";

describe("verifyRawEvidence verdict (venice)", () => {
  it("valid evidence -> status ok, level provider-attested", () => {
    const nonce = bytesToHex(randomBytes(32));
    const enclave = createVeniceMockEnclave(MODEL);
    const evidence = enclave.evidence(nonce);

    const verdict = verifyRawEvidence("venice", evidence, { upstreamModel: MODEL, nonce });

    expect(verdict.status).toBe("ok");
    expect(verdict.verification_level).toBe("provider-attested");
    // The vendor-root chain is deliberately not wired: never claim hardware-verified.
    expect(verdict.verification_level).not.toBe("hardware-verified");
    expect(verdict.privacy_modality).toBe("e2ee");
    expect(verdict.supports_client_opaque_e2ee).toBe(true);
    expect(verdict.nonce).toBe(nonce);
    expect(verdict.attested_encryption_key).toBe(enclave.enclavePubHex);
    expect(verdict.checks.every((c) => !c.required || c.passed)).toBe(true);
  });

  it("tampered nonce -> status failed", () => {
    const boundNonce = bytesToHex(randomBytes(32));
    const otherNonce = bytesToHex(randomBytes(32));
    const enclave = createVeniceMockEnclave(MODEL);
    const evidence = enclave.evidence(boundNonce);

    // The evidence was bound to boundNonce; verifying against a different fresh
    // nonce must fail closed on the nonce binding.
    const verdict = verifyRawEvidence("venice", evidence, { upstreamModel: MODEL, nonce: otherNonce });

    expect(verdict.status).toBe("failed");
    expect(verdict.verification_level).toBe("unverified");
    expect(verdict.reason).toBe("nonce_binding");
  });

  it("wrong model -> status failed", () => {
    const nonce = bytesToHex(randomBytes(32));
    const enclave = createVeniceMockEnclave(MODEL);
    const evidence = enclave.evidence(nonce);

    const verdict = verifyRawEvidence("venice", evidence, { upstreamModel: "some-other-model", nonce });
    expect(verdict.status).toBe("failed");
  });
});
