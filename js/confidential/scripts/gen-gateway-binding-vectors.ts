// Generate shared/vectors/gateway-binding.json, the cross-language known-answer
// test for the gateway attestation binding.
//
// The binding's canonical JSON is what the in-TEE producer hashes into the TDX
// quote's report_data. If JS and Python disagree about that serialization by even
// one byte, one of them rejects every genuine quote and the other could accept a
// digest it computed over different data. These vectors are the contract that
// stops that: both languages recompute `canonicalJson` and `bindingHash` from
// `binding` and must match byte for byte, and both must REJECT every case in
// `rejected` for the stated reason.
//
// Run: npm run gen:gateway-binding-vectors  (from js/confidential)

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  canonicalGatewayBindingJson,
  gatewayBindingHash,
  GATEWAY_BINDING_VERSION,
  type GatewayAttestationBinding
} from "../src/gateway/binding.js";

const accepted: Array<{ name: string; binding: GatewayAttestationBinding }> = [
  {
    name: "gateway-tls, no TD-owned certificate",
    binding: {
      v: GATEWAY_BINDING_VERSION,
      nonce: "9".repeat(64),
      app_id: "8acb516ec057ecfaf87392d616519347676b1b15",
      instance_id: "d4d2dfc6b44822af6d02e89a159b2eaf991d44a0",
      compose_hash: "fb8d315fa943ad513e378003cf119eee79081713201f393a56c4290a96fc8640",
      release_id: "anonrouter-tee@731c719",
      origin: "https://api.private.anonrouter.ai",
      key_alg: "x25519",
      public_key: "ab".repeat(32),
      transport: "gateway-tls",
      tls_spki_sha256: null
    }
  },
  {
    name: "in-tee-tls with a TD-owned certificate",
    binding: {
      v: GATEWAY_BINDING_VERSION,
      nonce: "0123456789abcdef".repeat(4),
      app_id: "8acb516ec057ecfaf87392d616519347676b1b15",
      instance_id: "d4d2dfc6b44822af6d02e89a159b2eaf991d44a0",
      compose_hash: "fb8d315fa943ad513e378003cf119eee79081713201f393a56c4290a96fc8640",
      release_id: "anonrouter-tee@731c719",
      origin: "https://api.private.anonrouter.ai",
      key_alg: "x25519",
      public_key: "cd".repeat(32),
      transport: "in-tee-tls",
      tls_spki_sha256: "115766d47c92c37eee1f41d687e93e827bc30eb281ceb374eabec4fd23693bc0"
    }
  },
  {
    name: "origin with an explicit port, ed25519 key",
    binding: {
      v: GATEWAY_BINDING_VERSION,
      nonce: "f".repeat(64),
      app_id: "0123456789abcdef0123456789abcdef01234567",
      instance_id: "fedcba9876543210fedcba9876543210fedcba98",
      compose_hash: "1".repeat(64),
      release_id: "anonrouter-tee@0.1.0-rc.1",
      origin: "https://tee.anonrouter.ai:8443",
      key_alg: "ed25519",
      public_key: "01".repeat(32),
      transport: "gateway-tls",
      tls_spki_sha256: null
    }
  },
  {
    name: "uppercase and 0x-prefixed inputs normalize before hashing",
    binding: {
      v: GATEWAY_BINDING_VERSION,
      nonce: "AB".repeat(32),
      app_id: "0x0123456789ABCDEF0123456789ABCDEF01234567",
      instance_id: "0xFEDCBA9876543210FEDCBA9876543210FEDCBA98",
      compose_hash: "0x" + "2".repeat(64),
      release_id: "anonrouter-tee@731c719",
      origin: "https://api.private.anonrouter.ai",
      key_alg: "secp256k1",
      public_key: "0x02" + "EF".repeat(32),
      transport: "gateway-tls",
      tls_spki_sha256: null
    } as unknown as GatewayAttestationBinding
  }
];

/** Inputs both languages must REFUSE, with the field each one is refused on. */
const rejected = [
  {
    name: "unknown field",
    field: "extra",
    binding: { ...accepted[0].binding, extra: "surprise" }
  },
  {
    name: "tls_spki_sha256 omitted rather than explicitly null",
    field: "tls_spki_sha256",
    binding: (() => {
      const { tls_spki_sha256: _omitted, ...rest } = accepted[0].binding;
      return rest;
    })()
  },
  {
    name: "in-tee-tls without a certificate digest",
    field: "tls_spki_sha256",
    binding: { ...accepted[0].binding, transport: "in-tee-tls" }
  },
  {
    name: "gateway-tls claiming a TD-owned certificate",
    field: "tls_spki_sha256",
    binding: { ...accepted[1].binding, transport: "gateway-tls" }
  },
  {
    name: "nonce shorter than 32 bytes",
    field: "nonce",
    binding: { ...accepted[0].binding, nonce: "ab".repeat(16) }
  },
  {
    name: "origin carrying a path",
    field: "origin",
    binding: { ...accepted[0].binding, origin: "https://api.private.anonrouter.ai/v1" }
  },
  {
    name: "origin with a trailing slash beyond the canonical form",
    field: "origin",
    binding: { ...accepted[0].binding, origin: "https://api.private.anonrouter.ai/v1/" }
  },
  {
    name: "unsupported binding version",
    field: "v",
    binding: { ...accepted[0].binding, v: 2 }
  },
  {
    name: "unknown key algorithm",
    field: "key_alg",
    binding: { ...accepted[0].binding, key_alg: "rsa" }
  },
  {
    name: "release id with a disallowed character",
    field: "release_id",
    binding: { ...accepted[0].binding, release_id: "anonrouter tee" }
  }
];

const document = {
  _readme: [
    "Known-answer vectors for the AnonRouter gateway attestation binding.",
    "Generated by js/confidential/scripts/gen-gateway-binding-vectors.ts.",
    "",
    "accepted[]: normalizeGatewayBinding(binding) must succeed, and both",
    "  canonicalGatewayBindingJson and gatewayBindingHash must reproduce the",
    "  recorded values EXACTLY. The hash is what a TD puts in report_data, so a",
    "  one-byte serialization difference is a total verification failure.",
    "",
    "rejected[]: normalizeGatewayBinding(binding) must raise, naming `field`."
  ],
  bindingVersion: GATEWAY_BINDING_VERSION,
  digestAlgorithm: "sha512",
  accepted: accepted.map((entry) => ({
    name: entry.name,
    binding: entry.binding,
    canonicalJson: canonicalGatewayBindingJson(entry.binding),
    bindingHash: gatewayBindingHash(entry.binding)
  })),
  rejected
};

const out = resolve(dirname(fileURLToPath(import.meta.url)), "../../../shared/vectors/gateway-binding.json");
writeFileSync(out, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${out} (${document.accepted.length} accepted, ${document.rejected.length} rejected)`);
