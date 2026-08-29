// Browser-safe structural parser for an Intel TDX v4 DCAP quote (the format Chutes,
// NEAR AI, and Venice all return). Uses only Uint8Array, never Node's Buffer, so it
// runs in a browser unchanged. It is deterministic byte-offset parsing, NOT
// signature verification: the ECDSA chain to Intel roots is not verified here, so a
// passing parse alone never earns a "hardware-verified" claim. Parsing never throws;
// it returns null so the caller fails closed.
//
// Layout (Intel TDX Quote v4, TD Report / TD10):
//   Quote Header            48 bytes  (version, att_key_type, tee_type, ...)
//   TD Quote Body          584 bytes  starting at offset 48:
//     tee_tcb_svn 16 | mr_seam 48 | mr_signer_seam 48 | seam_attributes 8 |
//     td_attributes 8 | xfam 8 | mr_td 48 | mr_config_id 48 | mr_owner 48 |
//     mr_owner_config 48 | rtmr0 48 | rtmr1 48 | rtmr2 48 | rtmr3 48 | report_data 64

import { base64ToBytes, bytesToHex, hexToBytes, isCanonicalBase64, isHex } from "../bytes.js";

export interface ParsedTdxQuote {
  version: number;
  teeType: number;
  /** TD build measurement (48-byte SHA-384), lowercase hex. */
  mrTd: string;
  mrConfigId: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  /** 64-byte report_data (nonce / key binding region), lowercase hex. */
  reportData: string;
  /** td_attributes (8 bytes), lowercase hex. */
  tdAttributes: string;
  /** True when the TUD.DEBUG bit (td_attributes bit 0) is set. */
  debugEnabled: boolean;
}

export const TDX_TEE_TYPE = 0x00000081;

const HEADER_LEN = 48;
const BODY_LEN = 584;
const QUOTE_MIN_LEN = HEADER_LEN + BODY_LEN;
/** Reject an oversized "quote" before allocating: a real TDX v4 quote is a few KB. */
const QUOTE_MAX_LEN = 64 * 1024;

// Offsets from the start of the quote (header included), per the layout above.
const OFF_TD_ATTRIBUTES = 48 + 16 + 48 + 48 + 8; // 168
const OFF_MR_TD = 48 + 136; // 184
const OFF_MR_CONFIG_ID = OFF_MR_TD + 48; // 232
const OFF_RTMR0 = OFF_MR_CONFIG_ID + 48 * 3; // 376
const OFF_REPORT_DATA = OFF_RTMR0 + 48 * 4; // 568

function decodeQuote(input: string): Uint8Array | null {
  const clean = input.trim();
  if (clean.length === 0 || clean.length > QUOTE_MAX_LEN * 2) return null;
  // Accept hex (NEAR/Venice intel_quote) or base64 (Chutes quote).
  if (isHex(clean) && clean.length % 2 === 0) {
    return hexToBytes(clean);
  }
  if (!isCanonicalBase64(clean)) return null;
  try {
    const bytes = base64ToBytes(clean);
    return bytes.length >= QUOTE_MIN_LEN ? bytes : null;
  } catch {
    return null;
  }
}

export function parseTdxQuote(input: unknown): ParsedTdxQuote | null {
  if (typeof input !== "string" || input.length === 0) return null;
  const buf = decodeQuote(input);
  if (!buf || buf.length < QUOTE_MIN_LEN || buf.length > QUOTE_MAX_LEN) return null;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const hex = (off: number, len: number) => bytesToHex(buf.subarray(off, off + len));
  return {
    version: view.getUint16(0, true),
    teeType: view.getUint32(4, true),
    mrTd: hex(OFF_MR_TD, 48),
    mrConfigId: hex(OFF_MR_CONFIG_ID, 48),
    rtmr0: hex(OFF_RTMR0, 48),
    rtmr1: hex(OFF_RTMR0 + 48, 48),
    rtmr2: hex(OFF_RTMR0 + 96, 48),
    rtmr3: hex(OFF_RTMR0 + 144, 48),
    reportData: hex(OFF_REPORT_DATA, 64),
    tdAttributes: hex(OFF_TD_ATTRIBUTES, 8),
    // TUD.DEBUG is bit 0 of the first td_attributes byte.
    debugEnabled: (buf[OFF_TD_ATTRIBUTES] & 0x01) === 0x01
  };
}

/** A single accepted-measurement entry (MRTD + RTMR0..3). */
export interface TdxMeasurementEntry {
  name: string;
  mrTd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
}

/** Whether a parsed quote's complete reviewed measurement identity (MRTD +
 *  RTMR0..3) matches an allowlist entry. RTMR3 is never ignored: a runtime change
 *  requires a new reviewed policy version. Returns the matched entry name or null. */
export function matchMeasurementAllowlist(
  quote: ParsedTdxQuote,
  allowlist: readonly TdxMeasurementEntry[]
): string | null {
  const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  for (const entry of allowlist) {
    if (
      eq(quote.mrTd, entry.mrTd)
      && eq(quote.rtmr0, entry.rtmr0)
      && eq(quote.rtmr1, entry.rtmr1)
      && eq(quote.rtmr2, entry.rtmr2)
      && eq(quote.rtmr3, entry.rtmr3)
    ) {
      return entry.name;
    }
  }
  return null;
}
