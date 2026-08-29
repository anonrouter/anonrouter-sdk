// SHA-384 for the test fixtures only. The verifier hashes through
// src/gateway/eventLog.ts; fixtures need their own so a builder bug cannot be
// masked by reusing the code under test for both sides of a comparison.

import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "../../src/bytes.js";

export function sha384Hex(input: Uint8Array): string {
  return bytesToHex(sha384(input));
}
