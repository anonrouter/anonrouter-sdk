// Generate shared/vectors/dcap.json.
//
// This script assembles the INPUTS only. Every expectation in the emitted file is
// stated independently of the implementation: the FMSPC is the six bytes this
// script embeds, the PCK chain is the PEM this script embeds, and the engine
// request/verdict shapes come from the engine's documented v1 contract rather
// than from whatever the adapter happens to return. That is deliberate. A vector
// file recorded from the code under test proves the two languages agree with
// each other but not that either is right; these cases pin the contract itself.
//
//   npx tsx scripts/gen-dcap-vectors.ts
//
// Read the resulting diff carefully. A changed expectation here is a changed wire
// contract with AnonRouter's reviewed DCAP engine, not a test fixup.

import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bytesToBase64, bytesToHex, hexToBytes } from "../src/bytes.js";
import { buildTdxQuoteBytes } from "../test/helpers/tdx-fixtures.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, "..", "..", "..", "shared", "vectors", "dcap.json");

/** DER for a made-up certificate carrying the Intel SGX FMSPC extension.
 *
 *  The parser looks for OID 1.2.840.113741.1.13.1.4 followed by an OCTET STRING
 *  of exactly 6 bytes, so the fixture embeds precisely that, plus a decoy: the
 *  same OID followed by a 4-byte OCTET STRING, which must NOT be read as an
 *  FMSPC. Getting that wrong would let a certificate steer TCB lookup at a
 *  different platform. */
function fmspcCertificateDer(fmspcHex: string, withDecoy: boolean): Uint8Array {
  const oid = hexToBytes("060a2a864886f84d010d0104");
  const parts: number[] = [0x30, 0x82, 0x01, 0x00];
  // Filler so the extension is not at a suspiciously convenient offset.
  for (let i = 0; i < 24; i += 1) parts.push(0x41 + (i % 26));
  if (withDecoy) {
    parts.push(...oid, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef);
  }
  parts.push(...oid, 0x04, 0x06, ...hexToBytes(fmspcHex));
  for (let i = 0; i < 16; i += 1) parts.push(0x30 + (i % 10));
  return new Uint8Array(parts);
}

function pem(der: Uint8Array): string {
  const body = bytesToBase64(der).replace(/(.{64})/g, "$1\n").trimEnd();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}

/** A quote with a PEM chain appended the way Intel cert data type 5 carries it,
 *  including the trailing NUL padding dstack leaves behind. */
function quoteWithChain(chain: string, trailingNuls = 8): string {
  const body = buildTdxQuoteBytes({
    mrTd: "11".repeat(48),
    rtmr0: "22".repeat(48),
    rtmr1: "33".repeat(48),
    rtmr2: "44".repeat(48),
    rtmr3: "55".repeat(48),
    reportData: "66".repeat(64)
  });
  const suffix = new TextEncoder().encode(chain);
  const buf = new Uint8Array(body.length + suffix.length + trailingNuls);
  buf.set(body, 0);
  buf.set(suffix, body.length);
  return bytesToHex(buf);
}

/** The contract: everything from the first BEGIN marker to the last END marker,
 *  inclusive, and nothing outside it. Stated here rather than read back from the
 *  extractor, so the vector pins the contract instead of the implementation. */
function armouredSpan(text: string): string {
  const begin = "-----BEGIN CERTIFICATE-----";
  const end = "-----END CERTIFICATE-----";
  return text.slice(text.indexOf(begin), text.lastIndexOf(end) + end.length);
}

const leaf = pem(fmspcCertificateDer("20a06f000000", true));
const intermediate = pem(fmspcCertificateDer("ffffffffffff", false));
const chain = `${leaf}\n${intermediate}\n`;
const chainSpan = armouredSpan(chain);
const quoteWithPck = quoteWithChain(chain);
const quoteWithoutPck = bytesToHex(buildTdxQuoteBytes({
  mrTd: "aa".repeat(48),
  rtmr0: "bb".repeat(48),
  rtmr1: "cc".repeat(48),
  rtmr2: "dd".repeat(48),
  rtmr3: "ee".repeat(48),
  reportData: "ff".repeat(64)
}));

/** A minimal collateral document. The values are shapes, not real Intel data. */
const collateral = {
  pck_crl_issuer_chain: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
  root_ca_crl: "3081aa",
  pck_crl: "3081bb",
  tcb_info_issuer_chain: "-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----\n",
  tcb_info: "{\"id\":\"TDX\",\"nextUpdate\":\"2026-09-29T23:23:57Z\"}",
  tcb_info_signature: "aabbcc",
  qe_identity_issuer_chain: "-----BEGIN CERTIFICATE-----\nR0hJ\n-----END CERTIFICATE-----\n",
  qe_identity: "{\"id\":\"TD_QE\",\"version\":2}",
  qe_identity_signature: "ddeeff",
  pck_certificate_chain: chainSpan
};

const document = {
  _readme: [
    "Known-answer vectors for the DCAP layer, loaded identically by the JS and Python",
    "suites. Three contracts are pinned here, and a divergence in any of them means the",
    "two languages would verify DIFFERENT things while printing the same verdict shape.",
    "",
    "1. quoteParsing   Locating the PCK certificate chain inside a quote and reading the",
    "                  FMSPC out of its leaf. The FMSPC selects which Intel TCB info",
    "                  applies, so reading the wrong one points the whole check at a",
    "                  different platform. The decoy case matters: the same OID appears",
    "                  with a 4-byte OCTET STRING, which is NOT an FMSPC.",
    "",
    "2. signedDocuments  Slicing the exact signed bytes out of an Intel PCS response.",
    "                  Intel signs the inner object verbatim, so a parse-and-reserialize",
    "                  would produce different bytes and a signature that no longer",
    "                  verifies. Brace matching must handle braces inside strings and",
    "                  escaped quotes.",
    "",
    "3. engineWire     The request the reviewed engine reads on stdin and the verdict it",
    "                  prints on stdout. `verified` must be a real boolean: the rejected",
    "                  cases are the ways a malformed verdict could otherwise be coerced",
    "                  into a pass.",
    "",
    "Regenerate with: npx tsx scripts/gen-dcap-vectors.ts (in js/confidential)."
  ],
  engineRequestVersion: 1,
  quoteParsing: {
    fixtures: {
      quoteWithPckChain: quoteWithPck,
      quoteWithoutPckChain: quoteWithoutPck,
      pckChain: chainSpan,
      leafFmspc: "20a06f000000"
    },
    cases: [
      {
        name: "reads the chain and the leaf FMSPC out of a quote",
        quote: quoteWithPck,
        expectedChain: chainSpan,
        expectedFmspc: "20a06f000000"
      },
      {
        name: "the same quote given as base64 yields the identical result",
        quote: bytesToBase64(hexToBytes(quoteWithPck)),
        expectedChain: chainSpan,
        expectedFmspc: "20a06f000000"
      },
      {
        name: "a quote with no PEM armour has no chain and no FMSPC",
        quote: quoteWithoutPck,
        expectedChain: null,
        expectedFmspc: null
      },
      {
        name: "input that is neither hex nor base64 is refused, not guessed at",
        quote: "not a quote!!",
        expectedChain: null,
        expectedFmspc: null
      },
      {
        name: "the FMSPC comes from the LEAF, so the second certificate's value is ignored",
        quote: quoteWithChain(`${intermediate}\n${leaf}\n`),
        expectedChain: armouredSpan(`${intermediate}\n${leaf}\n`),
        expectedFmspc: "ffffffffffff"
      }
    ]
  },
  signedDocuments: [
    {
      name: "slices the signed sub-object verbatim",
      body: "{\"tcbInfo\":{\"id\":\"TDX\",\"nextUpdate\":\"2026-09-29T23:23:57Z\"},\"signature\":\"AABBCC\"}",
      key: "tcbInfo",
      expectedDocument: "{\"id\":\"TDX\",\"nextUpdate\":\"2026-09-29T23:23:57Z\"}",
      expectedSignature: "aabbcc",
      expectedNextUpdateMs: Date.parse("2026-09-29T23:23:57Z")
    },
    {
      name: "a brace inside a string does not end the object",
      body: "{\"enclaveIdentity\":{\"note\":\"a } brace\",\"n\":1},\"signature\":\"01ff\"}",
      key: "enclaveIdentity",
      expectedDocument: "{\"note\":\"a } brace\",\"n\":1}",
      expectedSignature: "01ff",
      expectedNextUpdateMs: null
    },
    {
      name: "an escaped quote inside a string does not end the string",
      body: "{\"tcbInfo\":{\"note\":\"say \\\" then }\",\"nextUpdate\":\"2027-01-02T03:04:05Z\"},\"signature\":\"ab\"}",
      key: "tcbInfo",
      expectedDocument: "{\"note\":\"say \\\" then }\",\"nextUpdate\":\"2027-01-02T03:04:05Z\"}",
      expectedSignature: "ab",
      expectedNextUpdateMs: Date.parse("2027-01-02T03:04:05Z")
    },
    {
      name: "a missing key is an error, never an empty document",
      body: "{\"other\":{}}",
      key: "tcbInfo",
      expectedDocument: null,
      expectedSignature: null,
      expectedNextUpdateMs: null
    },
    {
      name: "an unbalanced object is an error",
      body: "{\"tcbInfo\":{\"id\":\"TDX\"",
      key: "tcbInfo",
      expectedDocument: null,
      expectedSignature: null,
      expectedNextUpdateMs: null
    }
  ],
  engineWire: {
    collateral,
    requests: [
      {
        name: "omits accepted_tcb_statuses when the caller pinned none",
        quote: "abcdef",
        nowSecs: 1_788_000_000,
        acceptedTcbStatuses: null,
        expected: {
          v: 1,
          quote: "abcdef",
          collateral,
          now_secs: 1_788_000_000
        }
      },
      {
        name: "carries the policy's accepted statuses so the engine and the policy agree",
        quote: "0011ff",
        nowSecs: 1_788_000_123,
        acceptedTcbStatuses: ["UpToDate", "SWHardeningNeeded"],
        expected: {
          v: 1,
          quote: "0011ff",
          collateral,
          now_secs: 1_788_000_123,
          accepted_tcb_statuses: ["UpToDate", "SWHardeningNeeded"]
        }
      },
      {
        name: "an empty accepted list is treated as unset, not as accept-nothing",
        quote: "00",
        nowSecs: 1_788_000_000,
        acceptedTcbStatuses: [],
        expected: {
          v: 1,
          quote: "00",
          collateral,
          now_secs: 1_788_000_000
        }
      }
    ],
    verdicts: [
      {
        name: "a verified verdict",
        stdout: "{\"v\":1,\"verified\":true,\"tcb_status\":\"UpToDate\",\"qe_tcb_status\":\"UpToDate\",\"platform_tcb_status\":\"UpToDate\",\"advisory_ids\":[],\"engine\":\"anonrouter-dcap-verifier/0.1.0 dcap-qvl/0.6.1\"}",
        expected: {
          verified: true,
          tcbStatus: "UpToDate",
          qeTcbStatus: "UpToDate",
          platformTcbStatus: "UpToDate",
          advisoryIds: [],
          hasReport: false,
          error: null,
          engine: "anonrouter-dcap-verifier/0.1.0 dcap-qvl/0.6.1"
        }
      },
      {
        name: "a refusal carries its content-free reason and the statuses it did read",
        stdout: "{\"v\":1,\"verified\":false,\"tcb_status\":\"OutOfDate\",\"qe_tcb_status\":\"UpToDate\",\"platform_tcb_status\":\"OutOfDate\",\"advisory_ids\":[\"INTEL-SA-00001\"],\"error\":\"tcb status OutOfDate is not accepted\",\"engine\":\"anonrouter-dcap-verifier/0.1.0 dcap-qvl/0.6.1\"}",
        expected: {
          verified: false,
          tcbStatus: "OutOfDate",
          qeTcbStatus: "UpToDate",
          platformTcbStatus: "OutOfDate",
          advisoryIds: ["INTEL-SA-00001"],
          hasReport: false,
          error: "tcb status OutOfDate is not accepted",
          engine: "anonrouter-dcap-verifier/0.1.0 dcap-qvl/0.6.1"
        }
      },
      {
        name: "an unknown engine name still parses; the field is an audit label, not a gate",
        stdout: "{\"verified\":true}",
        expected: {
          verified: true,
          tcbStatus: null,
          qeTcbStatus: null,
          platformTcbStatus: null,
          advisoryIds: [],
          hasReport: false,
          error: null,
          engine: "unknown"
        }
      },
      {
        name: "REJECTED: verified is the string \"true\"",
        stdout: "{\"verified\":\"true\"}",
        expected: null
      },
      {
        name: "REJECTED: verified is 1",
        stdout: "{\"verified\":1}",
        expected: null
      },
      {
        name: "REJECTED: verified is missing entirely",
        stdout: "{\"tcb_status\":\"UpToDate\"}",
        expected: null
      },
      {
        name: "REJECTED: the verdict is an array",
        stdout: "[{\"verified\":true}]",
        expected: null
      },
      {
        name: "REJECTED: output is not JSON",
        stdout: "verified",
        expected: null
      },
      {
        name: "REJECTED: no output at all (a crashed or absent engine)",
        stdout: "",
        expected: null
      }
    ]
  },
  platformTargets: [
    { platform: "linux", arch: "x64", target: "x86_64-unknown-linux-gnu" },
    { platform: "linux", arch: "arm64", target: "aarch64-unknown-linux-gnu" },
    { platform: "darwin", arch: "x64", target: "x86_64-apple-darwin" },
    { platform: "darwin", arch: "arm64", target: "aarch64-apple-darwin" },
    { platform: "win32", arch: "x64", target: "x86_64-pc-windows-msvc" },
    { platform: "linux", arch: "ia32", target: null }
  ]
};

writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`);
console.log(`wrote ${out}`);
