// Synthetic Intel TDX v4 quote builder for tests. Produces a byte-exact quote at
// the offsets the parser reads, so tests can construct evidence whose
// measurement/report_data bindings are fully controlled. NOT a real signed quote
// (the SDK never verifies the DCAP signature chain), which is exactly why these
// fixtures suffice for the binding-check tests.

import { bytesToBase64, bytesToHex, hexToBytes } from "../../src/bytes.js";

export interface TdxQuoteFields {
  teeType?: number;
  version?: number;
  debug?: boolean;
  mrTd: string;
  mrConfigId?: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  /** 64-byte report_data as 128 hex chars. */
  reportData: string;
}

function put(buf: Uint8Array, off: number, hex: string, len: number): void {
  const bytes = hexToBytes(hex);
  if (bytes.length !== len) throw new Error(`fixture field at ${off} must be ${len} bytes, got ${bytes.length}`);
  buf.set(bytes, off);
}

export function buildTdxQuoteBytes(fields: TdxQuoteFields): Uint8Array {
  const buf = new Uint8Array(632);
  const view = new DataView(buf.buffer);
  view.setUint16(0, fields.version ?? 4, true);
  view.setUint32(4, fields.teeType ?? 0x00000081, true);
  if (fields.debug) buf[168] = 0x01; // td_attributes bit0 = TUD.DEBUG
  put(buf, 184, fields.mrTd, 48);
  put(buf, 232, fields.mrConfigId ?? "00".repeat(48), 48);
  put(buf, 376, fields.rtmr0, 48);
  put(buf, 424, fields.rtmr1, 48);
  put(buf, 472, fields.rtmr2, 48);
  put(buf, 520, fields.rtmr3, 48);
  put(buf, 568, fields.reportData, 64);
  return buf;
}

export function buildTdxQuoteHex(fields: TdxQuoteFields): string {
  return bytesToHex(buildTdxQuoteBytes(fields));
}

export function buildTdxQuoteBase64(fields: TdxQuoteFields): string {
  return bytesToBase64(buildTdxQuoteBytes(fields));
}
