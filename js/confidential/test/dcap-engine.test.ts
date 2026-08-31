// The official DCAP adapter: the wire contract, engine discovery, and the ways it
// must fail closed.
//
// Every case here is about one property: an engine that did not run, ran wrong, or
// answered about something else must never become a pass. The shared vectors pin
// the wire contract itself so the Python twin cannot drift from it.

import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import vectors from "../../../shared/vectors/dcap.json" with { type: "json" };
import {
  buildDcapEngineRequest,
  createAnonRouterDcapVerifier,
  dcapPlatformTarget,
  describeDcapInstallation,
  engineReportDisagreement,
  fileSha256,
  parseDcapEngineVerdict,
  preparedDcapVerifier,
  resolveDcapVerifierBinary,
  runDcapEngine,
  DCAP_ENGINE_ENV,
  type DcapEngineVerdictV1
} from "../src/gateway/dcap/index.js";
import {
  extractFmspc,
  extractPckChain,
  normalizeQuoteHex,
  readNextUpdateMs,
  readSignedDocumentSignature,
  sliceSignedDocument,
  CollateralCache,
  CollateralError
} from "../src/gateway/dcap/collateral.js";
import { buildTdxQuoteHex } from "./helpers/tdx-fixtures.js";

const COLLATERAL = vectors.engineWire.collateral;

/** Write an executable shell script and return its path. */
function executableScript(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "anonrouter-dcap-"));
  const path = join(dir, "fake-engine");
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
}

/** A fake engine: consumes the request on stdin and prints a fixed verdict. */
function fakeEngine(stdout: string, exitCode = 0, extra = ""): string {
  return executableScript(
    `cat > /dev/null\n${extra}\ncat <<'ENGINE_EOF'\n${stdout}\nENGINE_EOF\nexit ${exitCode}`
  );
}

describe("shared vectors: quote -> PCK chain -> FMSPC", () => {
  for (const testCase of vectors.quoteParsing.cases) {
    it(testCase.name, () => {
      const chain = extractPckChain(testCase.quote);
      expect(chain).toBe(testCase.expectedChain);
      expect(chain === null ? null : extractFmspc(chain)).toBe(testCase.expectedFmspc);
    });
  }

  it("reads the FMSPC from the 6-byte OCTET STRING, never from the 4-byte decoy", () => {
    // The fixture leaf carries the same OID twice: once with a 4-byte value and
    // once with the real 6-byte FMSPC. Taking the first match would point the
    // whole TCB lookup at a platform that does not exist.
    const chain = extractPckChain(vectors.quoteParsing.fixtures.quoteWithPckChain)!;
    expect(chain).toContain("BEGIN CERTIFICATE");
    expect(extractFmspc(chain)).toBe("20a06f000000");
    expect(extractFmspc(chain)).not.toBe("deadbeef");
  });

  it("strips the NUL padding dstack leaves after the chain", () => {
    const chain = extractPckChain(vectors.quoteParsing.fixtures.quoteWithPckChain)!;
    expect(chain.includes("\0")).toBe(false);
    expect(chain.endsWith("-----END CERTIFICATE-----")).toBe(true);
  });

  it("normalizes hex and base64 to the same bytes", () => {
    const hex = vectors.quoteParsing.fixtures.quoteWithPckChain;
    const b64 = vectors.quoteParsing.cases.find((c) => c.name.includes("base64"))!.quote;
    expect(normalizeQuoteHex(b64)).toBe(hex);
    expect(normalizeQuoteHex(hex.toUpperCase())).toBe(hex);
    expect(normalizeQuoteHex("")).toBeNull();
    expect(normalizeQuoteHex(42)).toBeNull();
  });
});

describe("shared vectors: slicing Intel's signed documents", () => {
  for (const testCase of vectors.signedDocuments) {
    it(testCase.name, () => {
      if (testCase.expectedDocument === null) {
        expect(() => sliceSignedDocument(testCase.body, testCase.key)).toThrow(CollateralError);
        return;
      }
      const sliced = sliceSignedDocument(testCase.body, testCase.key);
      // The signature covers these exact bytes, so this is an identity check, not
      // a "parses to the same thing" check.
      expect(sliced).toBe(testCase.expectedDocument);
      expect(readSignedDocumentSignature(testCase.body)).toBe(testCase.expectedSignature);
      if (testCase.expectedNextUpdateMs === null) {
        expect(() => readNextUpdateMs(sliced)).toThrow(CollateralError);
      } else {
        expect(readNextUpdateMs(sliced)).toBe(testCase.expectedNextUpdateMs);
      }
    });
  }
});

describe("shared vectors: the engine request", () => {
  for (const testCase of vectors.engineWire.requests) {
    it(testCase.name, () => {
      const request = buildDcapEngineRequest(
        testCase.quote,
        COLLATERAL,
        testCase.nowSecs,
        testCase.acceptedTcbStatuses ?? undefined
      );
      expect(request).toEqual(testCase.expected);
    });
  }

  it("floors a fractional now_secs rather than emitting a float the engine cannot read", () => {
    expect(buildDcapEngineRequest("00", COLLATERAL, 1_788_000_000.9).now_secs).toBe(1_788_000_000);
  });

  it("copies the accepted statuses so a later caller mutation cannot change the sent request", () => {
    const statuses = ["UpToDate"];
    const request = buildDcapEngineRequest("00", COLLATERAL, 1, statuses);
    statuses.push("OutOfDate");
    expect(request.accepted_tcb_statuses).toEqual(["UpToDate"]);
  });
});

describe("shared vectors: parsing the engine verdict", () => {
  for (const testCase of vectors.engineWire.verdicts) {
    it(testCase.name, () => {
      const parsed = parseDcapEngineVerdict(testCase.stdout);
      if (testCase.expected === null) {
        // The whole point: a malformed verdict is unusable, not a weak pass.
        expect(parsed).toBeNull();
        return;
      }
      expect(parsed).not.toBeNull();
      expect(parsed!.verified).toBe(testCase.expected.verified);
      expect(parsed!.tcbStatus).toBe(testCase.expected.tcbStatus);
      expect(parsed!.qeTcbStatus).toBe(testCase.expected.qeTcbStatus);
      expect(parsed!.platformTcbStatus).toBe(testCase.expected.platformTcbStatus);
      expect(parsed!.advisoryIds).toEqual(testCase.expected.advisoryIds);
      expect(parsed!.report !== null).toBe(testCase.expected.hasReport);
      expect(parsed!.error).toBe(testCase.expected.error);
      expect(parsed!.engine).toBe(testCase.expected.engine);
    });
  }

  it("refuses an oversized verdict rather than parsing megabytes of it", () => {
    expect(parseDcapEngineVerdict(`{"verified":true,"pad":"${"a".repeat(300_000)}"}`)).toBeNull();
  });
});

describe("locating the engine", () => {
  it("uses an explicit path when it is executable", () => {
    const engine = fakeEngine('{"verified":true}');
    const resolved = resolveDcapVerifierBinary(engine, { env: {} });
    expect(resolved.path).toBe(engine);
    expect(resolved.origin).toBe("explicit");
  });

  it("an explicit path that does not exist resolves to NOTHING, never to another binary", () => {
    // The load-bearing rule. Falling through here would run an engine the caller
    // did not name, which is exactly the substitution this component prevents.
    const engine = fakeEngine('{"verified":true}');
    const resolved = resolveDcapVerifierBinary("/nonexistent/engine", {
      env: { [DCAP_ENGINE_ENV]: engine }
    });
    expect(resolved.path).toBeNull();
    expect(resolved.origin).toBe("none");
    expect(resolved.reason).toContain("/nonexistent/engine");
  });

  it("an environment variable that does not exist does not fall through to PATH either", () => {
    const resolved = resolveDcapVerifierBinary(undefined, {
      env: { [DCAP_ENGINE_ENV]: "/nonexistent/engine", PATH: "/usr/bin" }
    });
    expect(resolved.path).toBeNull();
    expect(resolved.reason).toContain(DCAP_ENGINE_ENV);
  });

  it("resolves from the environment when nothing explicit was given", () => {
    const engine = fakeEngine('{"verified":true}');
    const resolved = resolveDcapVerifierBinary(undefined, { env: { [DCAP_ENGINE_ENV]: engine } });
    expect(resolved.path).toBe(engine);
    expect(resolved.origin).toBe("environment");
  });

  it("resolves nothing at all when searchPath is off and no source was named", () => {
    const resolved = resolveDcapVerifierBinary(undefined, { searchPath: false, env: {} });
    expect(resolved.path).toBeNull();
    expect(resolved.origin).toBe("none");
  });

  it("hashes the resolved binary so an operator can compare it to a published digest", () => {
    const engine = fakeEngine('{"verified":true}');
    expect(fileSha256(engine)).toMatch(/^[0-9a-f]{64}$/);
    expect(fileSha256("/nonexistent/engine")).toBeNull();
  });

  it("maps hosts to the target triple a release artifact is named for", () => {
    for (const entry of vectors.platformTargets) {
      expect(dcapPlatformTarget(entry.platform, entry.arch)).toBe(entry.target);
    }
  });

  it("doctor reports the path that would actually run, and says what to do when there is none", () => {
    const engine = fakeEngine('{"verified":true}');
    const found = describeDcapInstallation({ binaryPath: engine });
    expect(found.available).toBe(true);
    expect(found.binaryPath).toBe(engine);
    expect(found.binarySha256).toMatch(/^[0-9a-f]{64}$/);

    const missing = describeDcapInstallation({ binaryPath: "/nonexistent/engine" });
    expect(missing.available).toBe(false);
    expect(missing.instructions.join(" ")).toContain("bundles no DCAP engine");
    // The instructions must never imply a silent downgrade is what happens.
    expect(missing.instructions.join(" ")).toContain("fails closed");
  });
});

describe("running the engine", () => {
  const quote = buildTdxQuoteHex({
    mrTd: "11".repeat(48), rtmr0: "22".repeat(48), rtmr1: "33".repeat(48),
    rtmr2: "44".repeat(48), rtmr3: "55".repeat(48), reportData: "66".repeat(64)
  });

  it("reads a verdict even when the engine exits non-zero, because 1 means not-verified", async () => {
    // The exit code is NOT the answer: the engine prints a verdict for 0 and 1
    // alike, and treating a non-zero exit as unparseable would lose the reason.
    const engine = fakeEngine('{"verified":false,"tcb_status":"OutOfDate","error":"tcb status OutOfDate is not accepted"}', 1);
    const verdict = await runDcapEngine(engine, buildDcapEngineRequest(quote, COLLATERAL, 1));
    expect(verdict.verified).toBe(false);
    expect(verdict.tcbStatus).toBe("OutOfDate");
    expect(verdict.error).toContain("OutOfDate");
  });

  it("a missing binary is a refusal, never a pass", async () => {
    const verdict = await runDcapEngine("/nonexistent/engine", buildDcapEngineRequest(quote, COLLATERAL, 1));
    expect(verdict.verified).toBe(false);
    expect(verdict.engine).toBe("unavailable");
  });

  it("output that is not JSON is a refusal", async () => {
    const engine = fakeEngine("segmentation fault", 139);
    const verdict = await runDcapEngine(engine, buildDcapEngineRequest(quote, COLLATERAL, 1));
    expect(verdict.verified).toBe(false);
  });

  it("a hung engine is refused at the deadline rather than hanging the caller", async () => {
    const engine = fakeEngine('{"verified":true}', 0, "sleep 5");
    const verdict = await runDcapEngine(engine, buildDcapEngineRequest(quote, COLLATERAL, 1), 300);
    expect(verdict.verified).toBe(false);
  }, 15_000);

  it("passes the request on stdin, so a quote never appears in the process table", async () => {
    // The engine echoes its own argv; an empty argv list proves the multi-kilobyte
    // request was not passed as an argument.
    const engine = fakeEngine('{"verified":true,"engine":"argv-probe"}', 0, 'test -z "$1" || exit 3');
    const verdict = await runDcapEngine(engine, buildDcapEngineRequest(quote, COLLATERAL, 1));
    expect(verdict.verified).toBe(true);
    expect(verdict.engine).toBe("argv-probe");
  });
});

describe("the prepared verifier is bound to one quote", () => {
  const quoteA = buildTdxQuoteHex({
    mrTd: "11".repeat(48), rtmr0: "22".repeat(48), rtmr1: "33".repeat(48),
    rtmr2: "44".repeat(48), rtmr3: "55".repeat(48), reportData: "66".repeat(64)
  });
  const quoteB = buildTdxQuoteHex({
    mrTd: "99".repeat(48), rtmr0: "88".repeat(48), rtmr1: "77".repeat(48),
    rtmr2: "66".repeat(48), rtmr3: "55".repeat(48), reportData: "44".repeat(64)
  });
  const pass: DcapEngineVerdictV1 = {
    verified: true, tcbStatus: "UpToDate", qeTcbStatus: "UpToDate",
    platformTcbStatus: "UpToDate", advisoryIds: [], report: null, error: null, engine: "test"
  };

  it("answers for the quote it ran on", () => {
    expect(preparedDcapVerifier(quoteA, pass, "test").verifyChain(quoteA).verified).toBe(true);
  });

  it("refuses any other quote, so one quote's pass cannot be replayed onto another", () => {
    const outcome = preparedDcapVerifier(quoteA, pass, "test").verifyChain(quoteB);
    expect(outcome.verified).toBe(false);
    expect(outcome.detail).toContain("prepared for a different quote");
  });

  it("compares on bytes, so the same quote spelled base64 is still the same quote", () => {
    const asBase64 = Buffer.from(quoteA, "hex").toString("base64");
    expect(preparedDcapVerifier(quoteA, pass, "test").verifyChain(asBase64).verified).toBe(true);
  });

  it("carries the engine's reason into the outcome so a refusal names itself", () => {
    const refused: DcapEngineVerdictV1 = { ...pass, verified: false, error: "TCBInfo expired" };
    expect(preparedDcapVerifier(quoteA, refused, "test").verifyChain(quoteA).detail).toBe("TCBInfo expired");
  });
});

describe("the engine's report is cross-checked against the quote we parsed", () => {
  const quote = buildTdxQuoteHex({
    mrTd: "11".repeat(48), rtmr0: "22".repeat(48), rtmr1: "33".repeat(48),
    rtmr2: "44".repeat(48), rtmr3: "55".repeat(48), reportData: "66".repeat(64)
  });
  const agreeing = {
    kind: "td10", tee_tcb_svn: "", mr_seam: "", mr_signer_seam: "", td_attributes: "",
    xfam: "", mr_td: "11".repeat(48), mr_config_id: "00".repeat(48), mr_owner: "",
    mr_owner_config: "", rtmr0: "22".repeat(48), rtmr1: "33".repeat(48),
    rtmr2: "44".repeat(48), rtmr3: "55".repeat(48), report_data: "66".repeat(64), debug: false
  };

  it("agrees when both read the same TD", () => {
    expect(engineReportDisagreement(quote, agreeing)).toBeNull();
  });

  it("a disagreement about report_data is fatal: one of us is looking at another quote", () => {
    expect(engineReportDisagreement(quote, { ...agreeing, report_data: "77".repeat(64) }))
      .toContain("report_data");
  });

  it("a disagreement about mr_td is fatal", () => {
    expect(engineReportDisagreement(quote, { ...agreeing, mr_td: "ab".repeat(48) })).toContain("mr_td");
  });

  it("no report at all is not a disagreement; the engine simply reported none", () => {
    expect(engineReportDisagreement(quote, null)).toBeNull();
  });
});

describe("createAnonRouterDcapVerifier fails closed on every path", () => {
  const quote = vectors.quoteParsing.fixtures.quoteWithPckChain;

  it("refuses when no engine can be resolved", async () => {
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: "/nonexistent/engine",
      collateral: COLLATERAL
    }).prepare(quote);
    const outcome = verifier.verifyChain(quote);
    expect(outcome.verified).toBe(false);
    expect(outcome.detail).toContain("/nonexistent/engine");
  });

  it("refuses when the engine's digest does not match the pin", async () => {
    const engine = fakeEngine('{"verified":true,"tcb_status":"UpToDate"}');
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      collateral: COLLATERAL,
      expectedBinarySha256: "00".repeat(32)
    }).prepare(quote);
    const outcome = verifier.verifyChain(quote);
    expect(outcome.verified).toBe(false);
    expect(outcome.detail).toContain("expectedBinarySha256");
  });

  it("accepts when the engine's digest matches the pin", async () => {
    const engine = fakeEngine('{"verified":true,"tcb_status":"UpToDate"}');
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      collateral: COLLATERAL,
      expectedBinarySha256: fileSha256(engine)!.toUpperCase()
    }).prepare(quote);
    expect(verifier.verifyChain(quote).verified).toBe(true);
  });

  it("refuses when collateral is absent and fetching is disabled", async () => {
    const engine = fakeEngine('{"verified":true}');
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      fetchCollateral: false
    }).prepare(quote);
    expect(verifier.verifyChain(quote).detail).toContain("fetching is disabled");
  });

  it("refuses when collateral could not be acquired, and says so", async () => {
    const engine = fakeEngine('{"verified":true}');
    const cache = new CollateralCache(async () => {
      throw new CollateralError("Intel PCS returned 503");
    });
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      collateralCache: cache
    }).prepare(quote);
    const outcome = verifier.verifyChain(quote);
    expect(outcome.verified).toBe(false);
    expect(outcome.detail).toContain("collateral unavailable");
  });

  it("refuses a verified verdict whose report describes a different TD", async () => {
    // A pass whose measurements disagree with the quote is worse than a refusal:
    // it would print hardware_verified for evidence nobody checked.
    const engine = fakeEngine(JSON.stringify({
      verified: true,
      tcb_status: "UpToDate",
      report: { mr_td: "ff".repeat(48), report_data: "00".repeat(64) }
    }));
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      collateral: COLLATERAL
    }).prepare(quote);
    const outcome = verifier.verifyChain(quote);
    expect(outcome.verified).toBe(false);
    expect(outcome.detail).toContain("disagree");
  });

  it("refuses a quote that is neither hex nor base64", async () => {
    const engine = fakeEngine('{"verified":true}');
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      collateral: COLLATERAL
    }).prepare("not a quote!!");
    expect(verifier.verifyChain("not a quote!!").verified).toBe(false);
  });

  it("passes the caller's accepted TCB statuses through to the engine", async () => {
    // Proven by having the fake engine echo what it read: if the SDK dropped the
    // field, an engine defaulting to UpToDate would refuse statuses the policy
    // allows, and a caller would be left debugging a disagreement they cannot see.
    const engine = executableScript(
      'request=$(cat)\ncase "$request" in\n'
      + "  *SWHardeningNeeded*) echo '{\"verified\":true,\"tcb_status\":\"SWHardeningNeeded\"}' ;;\n"
      + "  *) echo '{\"verified\":false,\"error\":\"statuses not forwarded\"}' ;;\nesac"
    );
    const verifier = await createAnonRouterDcapVerifier({
      binaryPath: engine,
      collateral: COLLATERAL
    }).prepare(quote, { acceptedTcbStatuses: ["UpToDate", "SWHardeningNeeded"] });
    const outcome = verifier.verifyChain(quote);
    expect(outcome.verified).toBe(true);
    expect(outcome.tcbStatus).toBe("SWHardeningNeeded");
  });
});

describe("the collateral cache is bounded by Intel's own signed expiry", () => {
  it("serves a cached entry until nextUpdate and refetches after it", async () => {
    let fetches = 0;
    const quote = vectors.quoteParsing.fixtures.quoteWithPckChain;
    const cache = new CollateralCache(async () => {
      fetches += 1;
      return {
        collateral: COLLATERAL,
        fmspc: "20a06f000000",
        nextUpdateMs: 2_000,
        fetchedAtMs: 1_000
      };
    });
    await cache.get(quote, 1_000);
    await cache.get(quote, 1_999);
    expect(fetches).toBe(1);
    // Past the signed nextUpdate the cache must not answer: the expiry comes from
    // what Intel signed, not from a policy constant we could quietly extend.
    await cache.get(quote, 2_001);
    expect(fetches).toBe(2);
    expect(cache.peek("20a06f000000")).not.toBeUndefined();
    cache.clear();
    expect(cache.peek("20a06f000000")).toBeUndefined();
  });
});
