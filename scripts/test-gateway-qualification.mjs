#!/usr/bin/env node
// gcp-tdx-native qualification tooling. Every artifact is SYNTHETIC and the
// DCAP "engine" below is a test double that is NOT Intel verification; it only
// exercises the plumbing that a real engine run would go through.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifySignedGatewayPolicy, packagedGatewayPolicyAuthority } from "../js/confidential/dist/gateway/authority.js";
import { loadGatewayPolicy } from "../js/confidential/dist/gateway/policy.js";
import {
  authenticodeSha384Edk2, classifyCcel, cmdlineFindings, EV, inspectUki, parseCcel, replayCcel, sha
} from "./gateway-qualification.mjs";
import {
  bootEvents, buildUki, encodeCcel, GOOD_CMDLINE, selfDescribing, SYNTHETIC, writeReferenceBoot
} from "./gateway-qualification-fixtures.mjs";
import {
  evaluatePromotionGate, prepareGatewayPolicyRelease, prepareTupleGatewayPolicyRelease, qualifyGcpPolicyCandidate,
  REVIEWED_DCAP_ENGINE_SHA256, REVIEWED_NATIVE_GUEST_VERIFIER_SHA256
} from "./gateway-policy-release.mjs";

const root = mkdtempSync(join(tmpdir(), "anonrouter-gcp-qualification-"));
let passed = 0;
const test = async (name, run) => { await run(); passed++; void name; };
try {
  // ---- Known answers agreed with the guest's native ar-guest-verify ----------
  const native = JSON.parse(readFileSync(new URL("./fixtures/gcp-qualification/native-reference.json", import.meta.url), "utf8"));
  const uki = buildUki(GOOD_CMDLINE(SYNTHETIC.verityRoot));
  await test("authenticode KAT", () => {
    assert.equal(authenticodeSha384Edk2(uki), native.uki_authenticode_sha384_edk2);
    // Trailing data and a certificate table: the table is excluded, trailing bytes are not.
    const signed = buildUki(GOOD_CMDLINE(SYNTHETIC.verityRoot), { trailing: Buffer.from("trail"), cert: Buffer.alloc(24, 7) });
    assert.equal(authenticodeSha384Edk2(signed), "8b434653cc41a195130c72c354def56d166750688a127425c1964baa2c7195c003bbdb70ad7db68bb6cea8791444b602");
    const patched = Buffer.from(uki); patched.writeUInt32LE(0x12345678, 0x80 + 24 + 64); // checksum only
    assert.equal(authenticodeSha384Edk2(patched), native.uki_authenticode_sha384_edk2);
  });
  await test("CCEL replay and classification KAT", () => {
    const log = parseCcel(encodeCcel(bootEvents(uki)));
    const pin = native.proposed_pin;
    assert.deepEqual(replayCcel(log), [pin.rtmr0, pin.rtmr1, pin.rtmr2, pin.rtmr3]);
    const c = classifyCcel(log, native.uki_authenticode_sha384_edk2);
    assert.deepEqual([c.findings, c.unlistedCode, c.rtmr1BootApplications], [[], [], [native.uki_authenticode_sha384_edk2]]);
  });

  // ---- CCEL refusals and semantic findings ------------------------------------
  await test("CCEL refuses structural tampering", () => {
    const good = encodeCcel(bootEvents(uki));
    const trailing = Buffer.from(good); trailing[trailing.length - 10] = 0x41;
    assert.throws(() => parseCcel(trailing), /eventlog_trailing/);
    assert.throws(() => replayCcel(parseCcel(encodeCcel([selfDescribing(0, EV.SEPARATOR, "\x01\x01\x01\x01")], 0))), /eventlog_mr_index/);
    assert.throws(() => parseCcel(encodeCcel([selfDescribing(7, EV.SEPARATOR, "\0\0\0\0")], 0)), /eventlog_mr_index/);
    const short = encodeCcel([selfDescribing(1, EV.SEPARATOR, "\0\0\0\0")], 0);
    assert.throws(() => parseCcel(short.subarray(0, short.length - 2)), /truncated/);
  });
  await test("CCEL semantics catch relabelling, extra boot applications, unknown and unlisted code", () => {
    const ukiDigest = authenticodeSha384Edk2(uki);
    const relabel = bootEvents(uki); relabel[0] = { ...relabel[0], digest: Buffer.alloc(48, 9) };
    assert.match(classifyCcel(parseCcel(encodeCcel(relabel)), ukiDigest).findings.join(), /does not hash to its own data/);
    const twice = [...bootEvents(uki), { ...bootEvents(uki)[3] }];
    assert.match(classifyCcel(parseCcel(encodeCcel(twice)), ukiDigest).findings.join(), /2 boot applications/);
    const unknown = [...bootEvents(uki), selfDescribing(1, 0xE, "partition")];
    assert.match(classifyCcel(parseCcel(encodeCcel(unknown)), ukiDigest).findings.join(), /unknown event type 0xe/);
    const driver = { mr: 1, type: EV.EFI_BOOT_SERVICES_DRIVER, digest: Buffer.alloc(48, 3), data: Buffer.from("rom") };
    const withDriver = parseCcel(encodeCcel([...bootEvents(uki), driver]));
    assert.equal(classifyCcel(withDriver, ukiDigest).unlistedCode.length, 1);
    assert.equal(classifyCcel(withDriver, ukiDigest, ["03".repeat(48)]).unlistedCode.length, 0);
  });

  // ---- UKI command line ------------------------------------------------------
  await test("UKI command line must name one verity root and carry no override", () => {
    assert.equal(inspectUki(uki).rootfsHash, SYNTHETIC.verityRoot);
    assert.deepEqual(cmdlineFindings(GOOD_CMDLINE(SYNTHETIC.verityRoot)), []);
    assert.equal(inspectUki(buildUki(`${GOOD_CMDLINE(SYNTHETIC.verityRoot)} dstack.rootfs_device=/dev/sdb systemd.debug_shell`)).cmdlineFindings.length, 2);
    assert.throws(() => inspectUki(buildUki(`${GOOD_CMDLINE(SYNTHETIC.verityRoot)} dstack.rootfs_hash=${"2".repeat(64)}`)), /uki_cmdline_duplicate/);
    // A second, unparsed command line hidden after the terminator inside the measured section.
    assert.throws(() => inspectUki(buildUki(`${GOOD_CMDLINE(SYNTHETIC.verityRoot)}\0rdinit=/bin/sh`)), /bytes after NUL/);
  });

  // ---- qualify-gcp ------------------------------------------------------------
  // Both helper programs below are SYNTHETIC test doubles: not Intel DCAP and not
  // the guest's native verifier. Their digests are never reviewed, which is the point.
  const script = (name, body) => {
    const path = join(root, name);
    writeFileSync(path, `#!/usr/bin/env node\n// SYNTHETIC test double.\n${body}\n`);
    chmodSync(path, 0o700);
    return path;
  };
  const engine = (mode) => script(`synthetic-dcap-engine-${mode}.mjs`, `
let input = ""; process.stdin.on("data", c => input += c).on("end", () => {
  const q = Buffer.from(JSON.parse(input).quote, "hex"); const h = (o, n) => q.subarray(o, o + n).toString("hex");
  const report = { td_attributes: h(168, 8), xfam: h(176, 8), mr_td: h(184, 48), mr_config_id: h(232, 48), mr_owner: h(280, 48),
    mr_owner_config: h(328, 48), rtmr0: h(376, 48), rtmr1: h(424, 48), rtmr2: h(472, 48), rtmr3: h(520, 48), report_data: h(568, 64) };
  if (${JSON.stringify(mode)} === "disagree-rtmr1") report.rtmr1 = "00".repeat(48);
  if (${JSON.stringify(mode)} === "disagree-xfam") report.xfam = "e71a060000000000";
  const tcb = ${JSON.stringify(mode)} === "outofdate" ? "OutOfDate" : "UpToDate";
  process.stdout.write(JSON.stringify({ verified: true, tcb_status: tcb, advisory_ids: [], report, engine: "synthetic-test-double" }));
});`);
  const lib = new URL("./gateway-qualification.mjs", import.meta.url).href;
  const nativeVerifier = (mode) => script(`synthetic-native-${mode}.mjs`, `
import { readFileSync } from "node:fs"; import { createHash } from "node:crypto";
const { authenticodeSha384Edk2 } = await import(${JSON.stringify(lib)});
const a = process.argv.slice(2); const flag = k => a[a.indexOf("--" + k) + 1];
const q = readFileSync(flag("quote")); const h = (o, n) => q.subarray(o, o + n).toString("hex");
const quoteSha = createHash("sha256").update(q).digest("hex");
const uki = ${JSON.stringify(mode)} === "lying" ? "00".repeat(48) : authenticodeSha384Edk2(readFileSync(flag("uki")));
process.stdout.write(JSON.stringify({ ok: true, result: { gate_n1_uki_in_rtmr1: true, quote_sha256: quoteSha,
  uki_authenticode_sha384_edk2: uki, proposed_pin: { release_id: flag("release-id"), shape: flag("shape"), mrtd: h(184, 48),
  rtmr0: h(376, 48), rtmr1: h(424, 48), rtmr2: h(472, 48), rtmr3: h(520, 48), reference_quote_sha256: quoteSha } } }));`);
  let caseIndex = 0;
  const qualify = async (mutate = {}, options = {}) => {
    const dir = mkdtempSync(join(root, `case-${caseIndex++}-`));
    const written = writeReferenceBoot(dir, mutate);
    options.after?.(dir, written);
    const candidate = await qualifyGcpPolicyCandidate(written.policy, written.bundle, { unqualifiedPlatformPilot: true, baseDir: dir,
      dcapBinary: engine(options.engine ?? "ok"), nativeVerifier: nativeVerifier(options.native ?? "ok") });
    const check = name => candidate.references[0].checks.find(c => c.name === name);
    const gate = (id, gates = candidate.promotionGate) => gates.find(g => g.id.startsWith(id)).status;
    return { candidate, check, gate, written, dir };
  };
  const failed = candidate => candidate.references[0].checks.filter(c => !c.passed).map(c => c.name);

  await test("tool-run checks pass, yet unreviewed helper programs can never satisfy P2-P4", async () => {
    const { candidate, gate } = await qualify();
    assert.deepEqual(failed(candidate), []);
    assert.equal(candidate.signable, false);
    assert.equal(candidate.platformQualified, false);
    assert.equal(candidate.promotable, false);
    assert.deepEqual(["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"].map(id => gate(id)),
      ["satisfied", "unmet", "unmet", "unmet", "external", "external", "external", "unmet"]);
    assert.match(candidate.promotionGate[1].evidence, /is not a reviewed build/);
    assert.equal(candidate.references[0].digests.ukiAuthenticodeSha384, native.uki_authenticode_sha384_edk2);
    assert.equal(candidate.references[0].digests.quoteSha256, native.quote_sha256);
    // The gate logic itself, with the double's digests treated as reviewed: P2-P4
    // then hold, and the candidate is still not promotable.
    const policy = loadGatewayPolicy(candidate.policy);
    const reviewed = { dcap: [candidate.engines.dcap], native: [candidate.engines.native] };
    const gates = evaluatePromotionGate(policy, candidate.references, candidate.engines, reviewed);
    assert.deepEqual(["P2", "P3", "P4", "P8"].map(id => gate(id, gates)), ["satisfied", "satisfied", "satisfied", "unmet"]);
    assert.equal(evaluatePromotionGate(policy, candidate.references, candidate.engines, reviewed, true).every(g => g.status === "satisfied"), false);
    assert.deepEqual([REVIEWED_DCAP_ENGINE_SHA256, REVIEWED_NATIVE_GUEST_VERIFIER_SHA256], [[], []]);
    // Nothing in a candidate is a gateway-policy payload or signing input.
    assert.equal(candidate.schema, "anonrouter.gateway-policy-qualification-candidate/v1");
    for (const forbidden of ["payload", "signingBytes", "signatures", "sequence", "manifestSha256"]) assert.equal(forbidden in candidate, false);
    const posing = { schema: "anonrouter.gateway-policy-envelope/v1", payload: JSON.stringify(candidate), signatures: [] };
    assert.throws(() => verifySignedGatewayPolicy(posing, packagedGatewayPolicyAuthority(), SYNTHETIC.origin, Date.now()));
  });
  await test("SELF-ASSERTED INPUTS: verdicts, digests, allowlists and pre-computed outputs are refused", async () => {
    for (const field of ["dcapVerdict", "nativeReference", "allowedCodeDigests", "quoteSha256", "ukiAuthenticodeSha384", "verified"]) {
      await assert.rejects(qualify({ reference: { [field]: field === "allowedCodeDigests" ? ["03".repeat(48)] : true } }), /not accepted as evidence/);
    }
    const dir = mkdtempSync(join(root, "bundle-"));
    const { policy, bundle } = writeReferenceBoot(dir);
    await assert.rejects(qualifyGcpPolicyCandidate(policy, { ...bundle, verdicts: [] }, { unqualifiedPlatformPilot: true, baseDir: dir }), /only schema and references/);
  });
  await test("SUBSTITUTION: a CCEL from another boot", async () => {
    const other = encodeCcel([selfDescribing(1, EV.EFI_ACTION, "another firmware"), ...bootEvents(uki)]);
    const { candidate } = await qualify({}, { after: dir => writeFileSync(join(dir, "ccel.bin"), other) });
    assert.deepEqual(failed(candidate), ["ccel_replays_quote"]);
  });
  await test("SUBSTITUTION: extra firmware code with no reviewed allowlist", async () => {
    const driver = { mr: 1, type: EV.EFI_BOOT_SERVICES_DRIVER, digest: Buffer.alloc(48, 3), data: Buffer.from("rom") };
    const { candidate } = await qualify({ ccel: encodeCcel([...bootEvents(uki), driver]) });
    assert.deepEqual(failed(candidate), ["ccel_events_classified"]);
  });
  await test("SUBSTITUTION: another boot key behind the same quote", async () => {
    const key = "e8".repeat(32);
    const { candidate } = await qualify({}, { after: (dir, written) => {
      const swapped = { ...written.binding, public_key: key, instance_id: sha("sha256", Buffer.from(key, "hex")) };
      writeFileSync(join(dir, "gateway-evidence.json"), JSON.stringify({ binding: swapped, quote: written.quote.toString("hex") }));
    } });
    assert.deepEqual(failed(candidate), ["report_data_binds_binding"]);
    const foreign = await qualify({ binding: { instance_id: "ab".repeat(32) } });
    assert.deepEqual(failed(foreign.candidate), ["instance_id_derives_from_boot_key"]);
  });
  await test("SUBSTITUTION: release A's boot presented as release B's tuple", async () => {
    const { candidate } = await qualify({}, { after: (_dir, written) => {
      const b = { ...written.tuple, tupleId: "synthetic-b@c4-standard-2", releaseId: "content@synthetic-b", appId: "6b".repeat(32),
        composeHash: "cd".repeat(32), rtmr1: "77".repeat(48) };
      written.policy.releaseTuples.push(b);
      written.bundle.references[0].tupleId = b.tupleId;
    } });
    assert.deepEqual(failed(candidate), ["binding_correlates_with_tuple", "quote_registers_match_tuple",
      "uki_cmdline_names_verity_root", "compose_digest_matches_tuple"]);
    assert.equal(candidate.promotionGate[0].status, "unmet");
  });
  await test("SUBSTITUTION: hashed inputs are recomputed, never read", async () => {
    const compose = await qualify({ compose: Buffer.from("{}\n") });
    assert.deepEqual(failed(compose.candidate), ["compose_digest_matches_tuple"]);
    const other = buildUki(GOOD_CMDLINE(SYNTHETIC.verityRoot).replace("panic=1", "panic=1 quiet"));
    const firmwareSawOther = await qualify({ ccel: encodeCcel(bootEvents(other)) });
    assert.deepEqual(failed(firmwareSawOther.candidate), ["rtmr1_boot_application_is_uki", "ccel_events_classified"]);
    const root2 = await qualify({ uki: buildUki(GOOD_CMDLINE("6b".repeat(32))) });
    assert.ok(failed(root2.candidate).includes("uki_cmdline_names_verity_root"));
  });
  await test("XFAM: a different feature set, and an engine that read a different XFAM", async () => {
    assert.deepEqual(failed((await qualify({ quote: { xfam: "e71a060000000000" } })).candidate), ["quote_registers_match_tuple"]);
    const engineXfam = (await qualify({}, { engine: "disagree-xfam" })).check("native_dcap_verified");
    assert.equal(engineXfam.passed, false); assert.match(engineXfam.detail, /disagree about xfam/);
  });
  await test("native DCAP refusals: out-of-date TCB and an engine that read different registers", async () => {
    assert.equal((await qualify({}, { engine: "outofdate" })).check("native_dcap_verified").passed, false);
    assert.match((await qualify({}, { engine: "disagree-rtmr1" })).check("native_dcap_verified").detail, /disagree about rtmr1/);
  });
  await test("RTMR3 extended and owner registers set", async () => {
    const extended = encodeCcel([...bootEvents(uki), selfDescribing(4, EV.EFI_ACTION, "runtime event")]);
    assert.ok(failed((await qualify({ ccel: extended })).candidate).includes("rtmr3_unextended"));
    assert.deepEqual(failed((await qualify({ quote: { mrOwner: "02".repeat(48) } })).candidate), ["owner_config_registers_zero"]);
  });
  await test("the native cross-check compares digests the tool ran it for", async () => {
    assert.deepEqual(failed((await qualify({}, { native: "lying" })).candidate), ["native_reference_digests_agree"]);
  });
  await test("qualify-gcp refuses without the pilot acknowledgement, for another platform, and any clock override", async () => {
    const dir = mkdtempSync(join(root, "refusals-"));
    const { policy, bundle } = writeReferenceBoot(dir);
    await assert.rejects(qualifyGcpPolicyCandidate(policy, bundle, { baseDir: dir }), /pilot/);
    await assert.rejects(qualifyGcpPolicyCandidate(policy, { ...bundle, references: [{ ...bundle.references[0], tupleId: "nope" }] },
      { unqualifiedPlatformPilot: true, baseDir: dir }), /unknown tuple/);
    const phala = JSON.parse(readFileSync(new URL("../shared/vectors/gateway-release-tuples.json", import.meta.url), "utf8"))
      .loadCases.find(c => c.name === "phala tuple form").policy;
    await assert.rejects(qualifyGcpPolicyCandidate(phala, bundle, { unqualifiedPlatformPilot: true, baseDir: dir }), /only gcp-tdx-native/);
    assert.throws(() => prepareGatewayPolicyRelease(Buffer.from("{}"), policy, 1, Date.now(), Date.now() + 1000));
    assert.throws(() => prepareTupleGatewayPolicyRelease([Buffer.from("{}")], policy, 1, Date.now(), Date.now() + 1000), /never signable/);
    writeFileSync(join(dir, "policy.json"), JSON.stringify(policy));
    const cli = args => spawnSync(process.execPath, [new URL("./gateway-policy-release.mjs", import.meta.url).pathname, "qualify-gcp",
      "--policy", join(dir, "policy.json"), "--evidence", join(dir, "evidence.json"), "--unqualified-platform-pilot", "acknowledged",
      "--out", join(dir, `candidate-${args.length}.json`), ...args], { encoding: "utf8" }).status;
    // Collateral validity is judged at the real time of the run, never a supplied one.
    assert.equal(cli(["--now-ms", "1"]), 1);
    assert.equal(cli([]), 0);
  });
  process.stdout.write(`GCP qualification tooling: ${passed} native-agreed KAT, CCEL/UKI, substitution and non-signable candidate groups passed.\n`);
} finally {
  rmSync(root, { recursive: true, force: true });
}
