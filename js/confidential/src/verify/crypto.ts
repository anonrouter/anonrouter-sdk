// Cryptographic primitives for the verifiers, using @noble/* only. Audited,
// dependency-light, and Web-platform safe, so the verifier core runs unchanged in a
// browser as well as in Node:
//   - SHA-256 / Keccak-256 via @noble/hashes
//   - secp256k1 point decompression + Ethereum-address derivation via @noble/curves
//     + keccak_256 (the standard address derivation, without pulling in ethers)
//   - Ed25519 signature verification via @noble/curves
//
// The Chutes verifier's X.509 certificate-possession check needs an ASN.1/X.509
// parser, which @noble does not provide. It comes from node:crypto, resolved
// synchronously when the runtime has it (see loadNodeCrypto). In Node the check is
// therefore required and always runs. In a pure browser build node:crypto is
// absent and ONLY that one sub-check degrades to "unavailable", while the ML-KEM
// key, nonce, and measurement bindings stay fully verified.

import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, utf8Encode } from "../bytes.js";

export function sha256Bytes(input: Uint8Array): Uint8Array {
  return sha256(input);
}

export function sha256Hex(input: Uint8Array | string): string {
  return bytesToHex(sha256(typeof input === "string" ? utf8Encode(input) : input));
}

/** Parse hex (with or without a 0x prefix) to bytes, throwing on malformed input. */
export function fromHex(hex: string): Uint8Array {
  const clean = hex.toLowerCase().replace(/^0x/, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) {
    throw new Error("invalid_hex");
  }
  return hexToBytes(clean);
}

/** Lowercase-hex equality that does not short-circuit on length (defense-in-depth
 *  for identity comparisons). Non-hex, empty, or mismatched-length inputs compare
 *  unequal. Used for every identity comparison the verifiers make. */
export function hexEqual(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  const x = a.toLowerCase().replace(/^0x/, "");
  const y = b.toLowerCase().replace(/^0x/, "");
  if (x.length !== y.length || x.length === 0) return false;
  if (!/^[0-9a-f]+$/.test(x) || !/^[0-9a-f]+$/.test(y)) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

/**
 * Derive the lowercase 0x-prefixed Ethereum address from a secp256k1 public key,
 * accepting a compressed (33-byte / 66-hex) or uncompressed (65-byte / 130-hex)
 * key. Address = keccak256(uncompressed_xy)[12:32]. This binds a provider-declared
 * signing address to the public key carried in the same attestation without
 * trusting the declared address by itself. Malformed keys fail closed (null).
 */
export function secp256k1AddressFromPublicKey(publicKey: string): string | null {
  try {
    const clean = publicKey.toLowerCase().replace(/^0x/, "");
    if (!/^(?:[0-9a-f]{66}|[0-9a-f]{130})$/.test(clean)) return null;
    const point = secp256k1.Point.fromBytes(hexToBytes(clean));
    const uncompressed = point.toBytes(false); // 65 bytes, leading 0x04
    const xy = uncompressed.subarray(1);
    return "0x" + bytesToHex(keccak_256(xy).subarray(12, 32));
  } catch {
    return null;
  }
}

/** Verify an Ed25519 signature (64 bytes) over `message` with a raw 32-byte key.
 *  Returns false on any malformed input rather than throwing. */
export function verifyEd25519(message: Uint8Array, signature: Uint8Array, rawPublicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, rawPublicKey);
  } catch {
    return false;
  }
}

/** Result of the optional Node X.509 certificate-possession check. `available`
 *  is false in a pure browser build (no node:crypto); the caller then degrades
 *  ONLY the possession sub-check while still verifying every other binding. */
export interface CertPossessionResult {
  available: boolean;
  /** SHA-256 hex of the certificate's DER SubjectPublicKeyInfo, or null. */
  spkiHash: string | null;
  /** True iff the RSA signature over `attestedBody` verified against the cert key. */
  possessionVerified: boolean;
  /** True iff `at` falls inside the certificate validity window. */
  certificateFresh: boolean;
}

type NodeCryptoLike = {
  X509Certificate: new (buf: Uint8Array) => {
    publicKey: { export(opts: { format: "der"; type: "spki" }): Uint8Array };
    validFrom: string;
    validTo: string;
  };
  verify: (
    algo: string,
    data: Uint8Array,
    key: unknown,
    signature: Uint8Array
  ) => boolean;
  constants: { RSA_PKCS1_PADDING: number };
};

let nodeCryptoCache: NodeCryptoLike | null | undefined;

function isNodeCryptoLike(mod: unknown): mod is NodeCryptoLike {
  return Boolean(mod) && typeof (mod as NodeCryptoLike).X509Certificate === "function"
    && typeof (mod as NodeCryptoLike).verify === "function";
}

/** Best-effort SYNCHRONOUS access to node:crypto, so the Chutes certificate
 *  possession check runs by default in Node without the caller having to opt in.
 *  Getting this wrong is not a crash, it is worse: the possession checks would
 *  silently downgrade to advisory and a verdict could read "ok" while three
 *  required bindings went unchecked. Two paths, both browser-safe:
 *
 *    1. `process.getBuiltinModule` (Node 22.3+), which works under ESM and CJS
 *       alike and needs no import. `process` is undefined in a browser.
 *    2. A CommonJS `require` on the global, for a Node CJS bundle.
 *
 *  If neither is available (a real browser, or a bundler that shims node:crypto
 *  out) this stays null and ONLY the possession sub-check degrades, which is the
 *  intended behavior there. `enableNodeCrypto()` remains available for older
 *  runtimes that have neither path. */
function loadNodeCrypto(): NodeCryptoLike | null {
  if (nodeCryptoCache !== undefined) return nodeCryptoCache ?? null;
  nodeCryptoCache = null;
  try {
    const getBuiltin = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } })
      .process?.getBuiltinModule;
    const builtin = typeof getBuiltin === "function" ? getBuiltin("node:crypto") : undefined;
    if (isNodeCryptoLike(builtin)) {
      nodeCryptoCache = builtin;
      return nodeCryptoCache;
    }
  } catch {
    /* not a Node runtime, or the builtin accessor is unavailable */
  }
  try {
    const req = (globalThis as { require?: (id: string) => unknown }).require;
    const mod = typeof req === "function" ? req("node:crypto") : undefined;
    if (isNodeCryptoLike(mod)) nodeCryptoCache = mod;
  } catch {
    nodeCryptoCache = null;
  }
  return nodeCryptoCache ?? null;
}

/** Explicitly inject (or clear, with null) the node:crypto provider used for the
 *  Chutes X.509 possession check. */
export function setNodeCryptoProvider(provider: NodeCryptoLike | null): void {
  nodeCryptoCache = provider;
}

/**
 * Enable the Node X.509 certificate-possession check under ESM by dynamically
 * importing node:crypto. A non-literal specifier keeps it out of static module
 * resolution so a browser build never has to resolve node:crypto. Returns true
 * when node:crypto became available. Safe to call repeatedly. In a browser (no
 * node:crypto) it returns false and only that one sub-check stays degraded.
 */
export async function enableNodeCrypto(): Promise<boolean> {
  if (isNodeCryptoLike(nodeCryptoCache)) return true;
  const specifier = "node:crypto";
  try {
    const mod = (await import(specifier)) as unknown;
    const resolved = isNodeCryptoLike(mod)
      ? mod
      : isNodeCryptoLike((mod as { default?: unknown }).default)
        ? (mod as { default: NodeCryptoLike }).default
        : null;
    if (resolved) {
      nodeCryptoCache = resolved;
      return true;
    }
  } catch {
    /* not a Node runtime; graceful degrade */
  }
  return false;
}

/**
 * Verify Chutes instance certificate possession with node:crypto when available.
 * Returns `available: false` (never throws) when node:crypto is not present, so a
 * browser build degrades ONLY this sub-check.
 */
export function verifyCertPossession(
  certificateDer: Uint8Array,
  attestedBody: Uint8Array,
  signature: Uint8Array,
  atMs: number
): CertPossessionResult {
  const nodeCrypto = loadNodeCrypto();
  if (!nodeCrypto) {
    return { available: false, spkiHash: null, possessionVerified: false, certificateFresh: false };
  }
  try {
    const cert = new nodeCrypto.X509Certificate(certificateDer);
    const spki = cert.publicKey.export({ format: "der", type: "spki" });
    const spkiHash = sha256Hex(spki);
    const possessionVerified = nodeCrypto.verify(
      "sha256",
      attestedBody,
      { key: cert.publicKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING },
      signature
    );
    const certificateFresh = Date.parse(cert.validFrom) <= atMs && atMs <= Date.parse(cert.validTo);
    return { available: true, spkiHash, possessionVerified, certificateFresh };
  } catch {
    // Malformed cert/key/signature: available but failed (fails the required check).
    return { available: true, spkiHash: null, possessionVerified: false, certificateFresh: false };
  }
}
