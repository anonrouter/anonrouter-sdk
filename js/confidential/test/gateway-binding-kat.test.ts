// Known-answer tests for the gateway attestation binding, read from the SHARED
// vectors that the Python package loads too.
//
// The binding's canonical JSON is what the in-TEE producer hashes into the TDX
// quote's report_data. If this package and the Python one disagree about that
// serialization by a single byte, one of them rejects every genuine quote and the
// other could accept a digest computed over data it never inspected. These
// vectors are the contract that makes that impossible to ship.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  canonicalGatewayBindingJson,
  gatewayBindingHash,
  GatewayBindingError,
  normalizeGatewayBinding,
  GATEWAY_BINDING_VERSION,
  type GatewayAttestationBinding
} from "../src/gateway/binding.js";

const vectorsPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../shared/vectors/gateway-binding.json"
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  bindingVersion: number;
  digestAlgorithm: string;
  accepted: Array<{ name: string; binding: GatewayAttestationBinding; canonicalJson: string; bindingHash: string }>;
  rejected: Array<{ name: string; field: string; binding: unknown }>;
};

describe("gateway binding known-answer vectors", () => {
  it("covers the binding version this package implements", () => {
    expect(vectors.bindingVersion).toBe(GATEWAY_BINDING_VERSION);
    expect(vectors.digestAlgorithm).toBe("sha512");
    expect(vectors.accepted.length).toBeGreaterThan(0);
    expect(vectors.rejected.length).toBeGreaterThan(0);
  });

  for (const vector of vectors.accepted) {
    it(`reproduces the canonical JSON and digest: ${vector.name}`, () => {
      expect(canonicalGatewayBindingJson(vector.binding)).toBe(vector.canonicalJson);
      expect(gatewayBindingHash(vector.binding)).toBe(vector.bindingHash);
      // 64 bytes: exactly what fits in a TDX quote's report_data field.
      expect(vector.bindingHash).toHaveLength(128);
    });
  }

  for (const vector of vectors.rejected) {
    it(`refuses, naming ${vector.field}: ${vector.name}`, () => {
      let thrown: unknown;
      try {
        normalizeGatewayBinding(vector.binding);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, "expected the binding to be refused").toBeInstanceOf(GatewayBindingError);
      expect((thrown as GatewayBindingError).field).toBe(vector.field);
    });
  }

  it("normalizes case and 0x prefixes before hashing, not after", () => {
    // Two spellings of the same identity must hash identically, or a client and a
    // TD that formatted the same value differently would never agree.
    const lower = vectors.accepted[0].binding;
    const shouted: GatewayAttestationBinding = {
      ...lower,
      nonce: lower.nonce.toUpperCase(),
      app_id: `0x${lower.app_id.toUpperCase()}`,
      compose_hash: `0x${lower.compose_hash.toUpperCase()}`
    };
    expect(gatewayBindingHash(shouted)).toBe(gatewayBindingHash(lower));
  });
});
