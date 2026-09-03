// What a Venice route that attests LESS than the others should be told about.
//
// THE LIVE CASE THIS COMES FROM. Three of Venice's nine E2EE routes
// (`deepseek/deepseek-v4-flash`, `qwen/qwen-3.6-35b-a3b-fp8`, `z-ai/glm-5.1`)
// return a perfectly well-formed quote, a real signing key and a live nonce —
// and an EMPTY `attestation` object. No `report_data`, no `evidence`, no
// `workload_keyset`. The other six populate all three. Measured six times each
// against production; the split is stable and does not move with load.
//
// So two required checks fail, and they SHOULD: a binding nobody stated is a
// binding that did not hold, and a signing key with no attested workload keyset
// is a key bound to nothing. Neither check is relaxed here and neither should
// be — this file exists to keep them failing while making them say why.
//
// The reason mattered enough to fix because the two situations call for
// opposite responses:
//
//   "did not match"     the provider asserted two contradictory things. Report
//                       the inconsistency; treat the route as suspect.
//   "carried nothing"   the provider asserted nothing. Ask them to emit the
//                       document, and withhold the route until they do.
//
// The old message said the first for both, which sends a reader hunting for a
// mismatch that does not exist.

import { describe, expect, it } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { verifyRawEvidence } from "../src/index.js";
import { bytesToHex } from "../src/bytes.js";

const NONCE = "ab".repeat(32);
const UPSTREAM = "e2ee-deepseek-v4-flash";

function ethAddress(pubHex: string): string {
  const pub = Uint8Array.from(Buffer.from(pubHex.slice(2), "hex"));
  return `0x${bytesToHex(keccak_256(pub).slice(-20))}`;
}

/** A TDX v4 quote with a chosen 64-byte report_data and the debug bit clear. */
function quoteHex(reportDataHex: string): string {
  const buf = Buffer.alloc(632);
  buf.writeUInt16LE(4, 0);
  buf.writeUInt32LE(0x81, 4);
  Buffer.from("11".repeat(48), "hex").copy(buf, 184);
  Buffer.from(reportDataHex, "hex").copy(buf, 568);
  return buf.toString("hex");
}

const sec = secp256k1.utils.randomSecretKey();
const pubHex = bytesToHex(secp256k1.getPublicKey(sec, false));
const address = ethAddress(pubHex);
const REPORT_DATA = address.slice(2).padEnd(64, "0") + NONCE;

/** Venice evidence with the nested attestation document under caller control. */
function veniceEvidence(nested: unknown): Record<string, unknown> {
  return {
    intel_quote: quoteHex(REPORT_DATA),
    nvidia_payload: "gpu-evidence",
    nonce: NONCE,
    model: UPSTREAM,
    signing_address: address,
    signing_algo: "ecdsa",
    signing_public_key: pubHex,
    ...(nested === undefined ? {} : { attestation: nested })
  };
}

const COMPLETE = {
  report_data: REPORT_DATA,
  evidence: { quote_report_data: REPORT_DATA },
  workload_keyset: {
    e2ee_public_keys: [{ algo: "secp256k1-aes-256-gcm-hkdf-sha256", public_key: pubHex }]
  }
};

function verdictFor(nested: unknown) {
  return verifyRawEvidence("venice", veniceEvidence(nested), {
    upstreamModel: UPSTREAM, nonce: NONCE, privacyModality: "e2ee"
  });
}

function detail(verdict: ReturnType<typeof verdictFor>, name: string): string {
  return verdict.checks.find((c) => c.name === name)?.detail ?? "";
}

describe("Venice evidence that carries the full nested attestation", () => {
  // THE POSITIVE CONTROL. Without it, every refusal below could equally mean
  // the fixture is broken, and the suite would measure nothing.
  it("verifies, so the refusals below are about the missing document", () => {
    const verdict = verdictFor(COMPLETE);
    expect(verdict.status).toBe("ok");
    expect(verdict.checks.filter((c) => c.required && !c.passed)).toEqual([]);
  });
});

describe("Venice evidence with an EMPTY nested attestation", () => {
  it("still refuses both bindings", () => {
    const verdict = verdictFor({});
    expect(verdict.status).toBe("failed");
    const failed = verdict.checks.filter((c) => c.required && !c.passed).map((c) => c.name);
    expect(failed).toContain("reported_quote_binding");
    expect(failed).toContain("workload_keyset_binding");
  });

  it("says the document was ABSENT rather than wrong", () => {
    const verdict = verdictFor({});
    expect(detail(verdict, "reported_quote_binding")).toMatch(/carried no nested attestation document/);
    expect(detail(verdict, "workload_keyset_binding")).toMatch(/attests no workload keyset/);
    // And specifically not the claim that something disagreed.
    expect(detail(verdict, "reported_quote_binding")).not.toMatch(/did not match/);
  });

  it("reads the same when the key is absent entirely, not merely empty", () => {
    const verdict = verdictFor(undefined);
    expect(verdict.status).toBe("failed");
    expect(detail(verdict, "reported_quote_binding")).toMatch(/carried no nested attestation document/);
  });
});

describe("Venice evidence whose nested attestation DISAGREES with the quote", () => {
  it("refuses, and says the values did not match", () => {
    // A present document restating a different report_data is a genuine
    // inconsistency, and must not be described as an absence.
    const verdict = verdictFor({ ...COMPLETE, report_data: "cd".repeat(64) });
    expect(verdict.status).toBe("failed");
    expect(detail(verdict, "reported_quote_binding")).toMatch(/did not match/);
    expect(detail(verdict, "reported_quote_binding")).not.toMatch(/carried no nested/);
  });

  it("distinguishes a document that merely omits report_data", () => {
    const { report_data: _omitted, ...withoutReportData } = COMPLETE;
    const verdict = verdictFor(withoutReportData);
    expect(verdict.status).toBe("failed");
    expect(detail(verdict, "reported_quote_binding")).toMatch(/omits report_data/);
  });

  it("refuses a keyset that exists but does not hold the signing key", () => {
    const verdict = verdictFor({
      ...COMPLETE,
      workload_keyset: {
        e2ee_public_keys: [{ algo: "secp256k1-aes-256-gcm-hkdf-sha256", public_key: `04${"11".repeat(64)}` }]
      }
    });
    expect(verdict.status).toBe("failed");
    expect(detail(verdict, "workload_keyset_binding")).toMatch(/does not contain the signing key/);
    expect(detail(verdict, "workload_keyset_binding")).not.toMatch(/attests no workload keyset/);
  });

  it("refuses a keyset carrying the right key under the wrong algorithm", () => {
    // The algorithm is part of the binding: the same bytes used for a different
    // scheme are not the key this route's encryption is bound to.
    const verdict = verdictFor({
      ...COMPLETE,
      workload_keyset: { e2ee_public_keys: [{ algo: "x25519-aes-256-gcm-hkdf-sha256", public_key: pubHex }] }
    });
    expect(verdict.status).toBe("failed");
    expect(detail(verdict, "workload_keyset_binding")).toMatch(/does not contain the signing key/);
  });
});
