// Known-answer-test parity: decrypt each shared crypto vector with the SDK's
// provider crypto and assert it equals the expected plaintext / JSON. These vectors
// were generated once from the proven private-repo crypto; both the JS and Python
// SDKs must agree byte-for-byte, so this is the cross-language parity contract.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { base64ToBytes, hexToBytes } from "../src/bytes.js";
import { providerCrypto } from "../src/index.js";

interface NearCase {
  provider: "near-ai";
  name: string;
  clientSecretHex: string;
  ciphertextHex: string;
  expectedPlaintext: string;
}
interface VeniceCase {
  provider: "venice";
  name: string;
  clientPrivateHex: string;
  ciphertextHex: string;
  expectedPlaintext: string;
}
interface ChutesCase {
  provider: "chutes";
  name: string;
  responseSecretKeyBase64: string;
  responseBlobBase64: string;
  expectedJson: unknown;
}
type CryptoCase = NearCase | VeniceCase | ChutesCase;

const vectors = JSON.parse(
  readFileSync(new URL("../../../shared/vectors/crypto-decrypt.json", import.meta.url), "utf8")
) as CryptoCase[];

describe("crypto KAT parity (shared/vectors/crypto-decrypt.json)", () => {
  it("loaded at least one case per provider", () => {
    const providers = new Set(vectors.map((v) => v.provider));
    expect(providers.has("near-ai")).toBe(true);
    expect(providers.has("venice")).toBe(true);
    expect(providers.has("chutes")).toBe(true);
  });

  for (const vector of vectors) {
    it(`${vector.provider}: ${vector.name}`, async () => {
      if (vector.provider === "near-ai") {
        const out = providerCrypto["near-ai"].decryptField(vector.ciphertextHex, hexToBytes(vector.clientSecretHex));
        expect(out).toBe(vector.expectedPlaintext);
      } else if (vector.provider === "venice") {
        const out = providerCrypto.venice.decrypt(vector.ciphertextHex, hexToBytes(vector.clientPrivateHex));
        expect(out).toBe(vector.expectedPlaintext);
      } else {
        const json = await providerCrypto.chutes.decryptResponseJson(
          base64ToBytes(vector.responseBlobBase64),
          base64ToBytes(vector.responseSecretKeyBase64)
        );
        expect(json).toStrictEqual(vector.expectedJson);
      }
    });
  }
});
