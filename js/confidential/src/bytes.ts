// Browser-safe byte utilities shared by every verifier and transport.
//
// This module deliberately uses only Web-platform primitives: Uint8Array,
// crypto.getRandomValues, TextEncoder/TextDecoder, and atob/btoa. It never pulls
// in Node's Buffer, node:crypto, or node:zlib, so this package runs unchanged in a
// browser, an Electron renderer, a service worker, or Node.

import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export { bytesToHex, concatBytes, hexToBytes, utf8ToBytes };

/** Narrow a possibly-ArrayBufferLike Uint8Array to one over a plain ArrayBuffer
 *  for Web APIs (fetch body, Compression Streams). Noble/WebCrypto arrays are
 *  always backed by a regular ArrayBuffer at runtime (never SharedArrayBuffer),
 *  so this is a safe type narrowing, not a copy. */
export function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

/** Cryptographically strong random bytes, from the Web Crypto CSPRNG only. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > 1_048_576) {
    throw new RangeError("randomBytes length out of range");
  }
  const out = new Uint8Array(length);
  // globalThis.crypto is available in browsers and in Node >= 18 (webcrypto).
  globalThis.crypto.getRandomValues(out);
  return out;
}

const HEX_RE = /^[0-9a-fA-F]*$/;

/** True iff `value` is even-length hex (upper or lower case). Empty is allowed. */
export function isHex(value: string): boolean {
  return value.length % 2 === 0 && HEX_RE.test(value);
}

/** Decode standard (RFC 4648) base64 to bytes without Node's Buffer. */
export function base64ToBytes(value: string): Uint8Array {
  // atob throws on invalid input; callers guard sizes/shape before this.
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/** Encode bytes to standard (RFC 4648) base64 without Node's Buffer. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  // Chunk to avoid "Maximum call stack" from String.fromCharCode(...bigArray).
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/** Canonical, strict base64 check: only [A-Za-z0-9+/] with correct padding. */
export function isCanonicalBase64(value: string): boolean {
  if (value.length === 0 || value.length % 4 !== 0) return false;
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });
const TEXT_DECODER_LOSSY = new TextDecoder("utf-8", { fatal: false });

export function utf8Encode(text: string): Uint8Array {
  return TEXT_ENCODER.encode(text);
}

/** Strict UTF-8 decode. Throws on malformed sequences rather than substituting. */
export function utf8Decode(bytes: Uint8Array): string {
  return TEXT_DECODER.decode(bytes);
}

/** Non-fatal UTF-8 decode for decrypted streamed content deltas: a provider may
 *  split a multi-byte codepoint across two independently-encrypted deltas, so
 *  substituting rather than throwing keeps one split character from failing an
 *  otherwise valid response. */
export function utf8DecodeLossy(bytes: Uint8Array): string {
  return TEXT_DECODER_LOSSY.decode(bytes);
}

/** Length-independent byte comparison for identity/tag checks (defense-in-depth). */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Best-effort zeroing of sensitive byte arrays. Only the backing storage of the
 *  passed arrays is cleared; callers must pass the top-level allocations (not
 *  subarray views they still need). V8 may retain copies, so this is defense in
 *  depth, not a guarantee. */
export function zeroize(...arrays: Array<Uint8Array | null | undefined>): void {
  for (const array of arrays) {
    if (array && array.length > 0) array.fill(0);
  }
}
