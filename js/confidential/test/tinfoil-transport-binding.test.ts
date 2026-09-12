// `verifyTinfoilEnclave()` has to be worth more than re-reading a document.
//
// The first half runs the pin against a REAL TLS server with a real certificate,
// because the whole claim is about what happens on a live connection and a mock
// socket cannot falsify it. A matching key must be observed and returned; a
// different key must be refused, and must leave no observation behind.
//
// The second half wires that into the verifier and mutates one input at a time.
// Each seam that could quietly turn the pin off gets its own case, since a
// function that fell back to "the document says so" would still pass a test that
// only checked the happy path.

import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  observeTinfoilTlsSpki,
  verifyTinfoilEnclave,
  TinfoilTlsPinError,
  TinfoilTlsUnavailableError,
  type TinfoilSdkVerifier,
  type TinfoilVerificationDocument
} from "../src/index.js";

const CODE_FP = "6d".repeat(48);
const TLS_FP = "19".repeat(32);
const HOST = "inference.tinfoil.sh";

/** The document the official verifier returns, WITHOUT any transport binding:
 *  attaching one is this wrapper's job, not the document's. */
function officialDocument(over: Partial<TinfoilVerificationDocument> = {}): TinfoilVerificationDocument {
  return {
    schemaVersion: 1,
    securityVerified: true,
    enclaveHost: HOST,
    selectedRouterEndpoint: `https://${HOST}`,
    configRepo: "tinfoilsh/confidential-model-router",
    releaseTag: "v99.0.0",
    releaseDigest: "7d".repeat(32),
    codeFingerprint: CODE_FP,
    enclaveFingerprint: CODE_FP,
    enclaveMeasurement: { tlsPublicKeyFingerprint: TLS_FP },
    tlsPublicKey: TLS_FP,
    verifier: { name: "@tinfoilsh/verifier", version: "1.2.1" },
    steps: Object.fromEntries([
      "fetchDigest",
      "verifyCode",
      "verifyEnclave",
      "compareMeasurements",
      "verifyCertificate"
    ].map((name) => [name, { status: "success" }])),
    ...over
  };
}

/** The specific cause a fail-closed verdict reports. `reason` is always the
 *  required check that could not be satisfied (`evidence_present`); the cause
 *  travels in that check's detail. */
function cause(verdict: { checks: Array<{ name: string; detail?: string }> }): string | undefined {
  return verdict.checks.find((c) => c.name === "evidence_present")?.detail;
}

function stubVerifier(doc: TinfoilVerificationDocument | null): TinfoilSdkVerifier {
  return {
    verify: async () => undefined,
    getVerificationDocument: () => doc ?? undefined
  };
}

/** A throwaway HTTPS server with a real self-signed certificate, so the pin runs
 *  against an actual handshake instead of a stand-in for one. */
async function withTlsServer<T>(
  run: (server: { origin: string; spki: string; ca: string }) => Promise<T>
): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "anonrouter-tinfoil-tls-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath, "-out", certPath, "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"
  ], { stdio: "ignore" });
  const key = readFileSync(keyPath, "utf8");
  const cert = readFileSync(certPath, "utf8");
  const server = createServer({ key, cert }, (_request, response) => response.end("ok"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("TLS test server did not bind");
  const spki = createHash("sha256")
    .update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  try {
    return await run({ origin: `https://localhost:${address.port}`, spki, ca: cert });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("observeTinfoilTlsSpki against a real TLS peer", () => {
  it("returns the key it actually saw when the pin matches", async () => {
    await withTlsServer(async ({ origin, spki, ca }) => {
      const observed = await observeTinfoilTlsSpki({ origin, expectedTlsSpki: spki, ca, timeoutMs: 10_000 });
      expect(observed).toBe(spki);
    });
  }, 30_000);

  it("refuses a peer whose key is not the attested one", async () => {
    await withTlsServer(async ({ origin, ca }) => {
      await expect(observeTinfoilTlsSpki({
        origin, expectedTlsSpki: "00".repeat(32), ca, timeoutMs: 10_000
      })).rejects.toBeInstanceOf(TinfoilTlsPinError);
    });
  }, 30_000);

  it("refuses a peer that fails ordinary PKI validation even with the right key", async () => {
    // The pin is IN ADDITION to normal certificate and hostname checking, not
    // instead of it. Dropping the CA leaves a self-signed certificate that the
    // standard check rejects before the SPKI is ever compared.
    await withTlsServer(async ({ origin, spki }) => {
      await expect(observeTinfoilTlsSpki({ origin, expectedTlsSpki: spki, timeoutMs: 10_000 }))
        .rejects.toThrow();
    });
  }, 30_000);

  it("refuses a plaintext origin and a malformed pin without opening a socket", async () => {
    await expect(observeTinfoilTlsSpki({ origin: "http://inference.tinfoil.sh", expectedTlsSpki: TLS_FP }))
      .rejects.toBeInstanceOf(TinfoilTlsPinError);
    await expect(observeTinfoilTlsSpki({ origin: `https://${HOST}`, expectedTlsSpki: "nope" }))
      .rejects.toBeInstanceOf(TinfoilTlsPinError);
  });
});

describe("verifyTinfoilEnclave binds the document to a connection it made itself", () => {
  it("reaches sdk-verified only after observing the attested key on the wire", async () => {
    const probed: Array<{ origin: string; expectedTlsSpki: string }> = [];
    const verdict = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => stubVerifier(officialDocument()),
        observeTlsSpki: async ({ origin, expectedTlsSpki }) => {
          probed.push({ origin, expectedTlsSpki });
          return TLS_FP;
        }
      }
    });

    expect(verdict.status).toBe("ok");
    expect(verdict.verification_level).toBe("sdk-verified");
    expect(verdict.hardware_type).toBe("amd-sev-snp");
    // Pinned against the key in the VERIFIED report, at the fixed origin.
    expect(probed).toEqual([{ origin: `https://${HOST}`, expectedTlsSpki: TLS_FP }]);
  });

  it("fails closed when the pinned observation refuses the peer", async () => {
    const verdict = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => stubVerifier(officialDocument()),
        observeTlsSpki: async () => { throw new TinfoilTlsPinError(); }
      }
    });
    expect(verdict.status).toBe("failed");
    expect(cause(verdict)).toBe("tinfoil_tls_pin_mismatch");
    expect(verdict.verification_level).toBe("unverified");
  });

  it("fails closed, with its own reason, in a runtime that cannot observe TLS", async () => {
    // A browser cannot read a peer certificate. The honest outcome is a refusal
    // naming that, never a verdict that skipped the pin.
    const verdict = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => stubVerifier(officialDocument()),
        observeTlsSpki: async () => { throw new TinfoilTlsUnavailableError(); }
      }
    });
    expect(verdict.status).toBe("failed");
    expect(cause(verdict)).toBe("tinfoil_tls_observation_unsupported");
  });

  it("never trusts a transport binding the document supplied about itself", async () => {
    // The document arrives claiming its own key was observed. If that claim were
    // honoured, the whole point of this function would evaporate: a hostile
    // document would carry its own proof. The observation must be OURS.
    const selfAsserted = officialDocument({
      transportBinding: {
        mode: "tls-pinned",
        endpointIdentity: HOST,
        observedTlsSpki: TLS_FP,
        verified: true
      }
    });
    const verdict = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => stubVerifier(selfAsserted),
        observeTlsSpki: async () => { throw new TinfoilTlsPinError(); }
      }
    });
    expect(verdict.status).toBe("failed");
    expect(cause(verdict)).toBe("tinfoil_tls_pin_mismatch");
  });

  it("refuses to probe at all when the report carries no usable TLS key", async () => {
    const verdict = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => stubVerifier(officialDocument({ enclaveMeasurement: {} })),
        observeTlsSpki: async () => { throw new Error("must not be reached"); }
      }
    });
    expect(verdict.status).toBe("failed");
    expect(cause(verdict)).toBe("tinfoil_attested_tls_key_unavailable");
  });

  it("fails closed when the official verifier throws or returns no document", async () => {
    const threw = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => ({
          verify: async () => { throw new Error("attestation refused"); },
          getVerificationDocument: () => undefined
        }),
        observeTlsSpki: async () => TLS_FP
      }
    });
    expect(cause(threw)).toBe("tinfoil_sdk_verification_unavailable");

    const empty = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => stubVerifier(null),
        observeTlsSpki: async () => TLS_FP
      }
    });
    expect(cause(empty)).toBe("tinfoil_sdk_verification_unavailable");

    // A constructor that throws is a verifier we do not have, not an exception
    // for the caller to handle. Fail closed like every other missing check.
    const constructorThrew = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      dependencies: {
        verifierFactory: () => { throw new Error("cannot construct"); },
        observeTlsSpki: async () => TLS_FP
      }
    });
    expect(constructorThrew.status).toBe("failed");
    expect(cause(constructorThrew)).toBe("tinfoil_sdk_verification_unavailable");
  });

  it("refuses an unsupported enclave host or repository before doing anything", async () => {
    const wrongHost = await verifyTinfoilEnclave({
      enclaveHost: "inference.attacker.example",
      dependencies: {
        verifierFactory: () => { throw new Error("must not be reached"); },
        observeTlsSpki: async () => { throw new Error("must not be reached"); }
      }
    });
    expect(cause(wrongHost)).toBe("tinfoil_enclave_host_not_supported");

    const wrongRepo = await verifyTinfoilEnclave({
      enclaveHost: HOST,
      configRepo: "attacker/confidential-model-router",
      dependencies: {
        verifierFactory: () => { throw new Error("must not be reached"); },
        observeTlsSpki: async () => { throw new Error("must not be reached"); }
      }
    });
    expect(cause(wrongRepo)).toBe("tinfoil_config_repo_not_supported");
  });
});
