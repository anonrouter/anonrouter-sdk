// TDX quote parser parity: parse each shared quote vector (hex or base64) and assert
// the extracted fields match. The parser is deterministic byte-offset parsing, so
// the JS and Python SDKs must agree on every field.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseTdxQuote } from "../src/index.js";

interface TdxVector {
  name: string;
  encoding: "hex" | "base64";
  quote: string;
  expected: {
    teeType: number;
    debugEnabled: boolean;
    mrTd: string;
    mrConfigId?: string;
    rtmr0?: string;
    rtmr1?: string;
    rtmr2?: string;
    rtmr3?: string;
    reportData?: string;
  };
}

const vectors = JSON.parse(
  readFileSync(new URL("../../../shared/vectors/tdx-quotes.json", import.meta.url), "utf8")
) as TdxVector[];

describe("TDX quote parse parity (shared/vectors/tdx-quotes.json)", () => {
  for (const vector of vectors) {
    it(vector.name, () => {
      const parsed = parseTdxQuote(vector.quote);
      expect(parsed).not.toBeNull();
      if (!parsed) return;
      expect(parsed.teeType).toBe(vector.expected.teeType);
      expect(parsed.debugEnabled).toBe(vector.expected.debugEnabled);
      expect(parsed.mrTd).toBe(vector.expected.mrTd);
      if (vector.expected.mrConfigId) expect(parsed.mrConfigId).toBe(vector.expected.mrConfigId);
      if (vector.expected.rtmr0) expect(parsed.rtmr0).toBe(vector.expected.rtmr0);
      if (vector.expected.rtmr1) expect(parsed.rtmr1).toBe(vector.expected.rtmr1);
      if (vector.expected.rtmr2) expect(parsed.rtmr2).toBe(vector.expected.rtmr2);
      if (vector.expected.rtmr3) expect(parsed.rtmr3).toBe(vector.expected.rtmr3);
      if (vector.expected.reportData) expect(parsed.reportData).toBe(vector.expected.reportData);
    });
  }

  it("returns null on junk input (fail closed)", () => {
    expect(parseTdxQuote("not a quote")).toBeNull();
    expect(parseTdxQuote("")).toBeNull();
    expect(parseTdxQuote(42)).toBeNull();
  });
});
