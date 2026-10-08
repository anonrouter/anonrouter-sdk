#!/usr/bin/env node
// gcp-tdx-native qualification tooling. Every artifact is SYNTHETIC and the
// DCAP "engine" below is a test double that is NOT Intel verification; it only
// exercises the plumbing that a real engine run would go through.
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifySignedGatewayPolicy, packagedGatewayPolicyAuthority } from "../js/confidential/dist/gateway/authority.js";
import { loadGatewayPolicy } from "../js/confidential/dist/gateway/policy.js";
import {
  authenticodeSha384Edk2, classifyCcel, cmdlineFindings, EV, inspectUki, parseCcel, replayCcel
} from "./gateway-qualification.mjs";
import {
  bootEvents, buildUki, encodeCcel, GOOD_CMDLINE, selfDescribing, SYNTHETIC, writeReferenceBoot
} from "./gateway-qualification-fixtures.mjs";
import { prepareGatewayPolicyRelease, prepareTupleGatewayPolicyRelease, qualifyGcpPolicyCandidate } from "./gateway-policy-release.mjs";

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
  const engine = (mode) => {
    const path = join(root, `synthetic-dcap-engine-${mode}.mjs`);
    writeFileSync(path, `#!/usr/bin/env node
// SYNTHETIC test double, NOT Intel DCAP verification.
let input = ""; process.stdin.on("data", c => input += c).on("end", () => {
  const q = Buffer.from(JSON.parse(input).quote, "hex"); const h = (o, n) => q.subarray(o, o + n).toString("hex");
  const report = { mr_td: h(184, 48), mr_config_id: h(232, 48), rtmr0: h(376, 48), rtmr1: h(424, 48), rtmr2: h(472, 48),
    rtmr3: h(520, 48), report_data: h(568, 64) };
  if (${JSON.stringify(mode)} === "disagree") report.rtmr1 = "00".repeat(48);
  const tcb = ${JSON.stringify(mode)} === "outofdate" ? "OutOfDate" : "UpToDate";
  process.stdout.write(JSON.stringify({ verified: true, tcb_status: tcb, advisory_ids: [], report, engine: "synthetic-test-double" }));
});\n`);
    chmodSync(path, 0o700);
    return path;
  };
  const NOW = 1_791_327_000_000;
  let caseIndex = 0;
  const qualify = async (mutate = {}, options = {}) => {
    const dir = mkdtempSync(join(root, `case-${caseIndex++}-`));
    const written = writeReferenceBoot(dir, mutate);
    if (options.native !== false) {
      writeFileSync(join(dir, "native.json"), JSON.stringify(options.native ?? native));
      written.bundle.references[0].nativeReference = "native.json";
    }
    const candidate = await qualifyGcpPolicyCandidate(written.policy, written.bundle,
      { unqualifiedPlatformPilot: true, baseDir: dir, nowMs: NOW, ...(options.engine ? { dcapBinary: engine(options.engine) } : {}) });
    const check = name => candidate.references[0].checks.find(c => c.name === name);
    const gate = id => candidate.promotionGate.find(g => g.id.startsWith(id)).status;
    return { candidate, check, gate, written };
  };

  await test("a complete synthetic reference satisfies every tool-checkable gate and stays non-promotable", async () => {
    const { candidate, gate } = await qualify({}, { engine: "ok" });
    assert.deepEqual(candidate.references[0].checks.filter(c => !c.passed), []);
    assert.equal(candidate.signable, false);
    assert.equal(candidate.platformQualified, false);
    assert.equal(candidate.promotable, false);
    assert.deepEqual(["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"].map(gate),
      ["satisfied", "satisfied", "satisfied", "satisfied", "external", "external", "external", "unmet"]);
    assert.equal(candidate.references[0].digests.ukiAuthenticodeSha384, native.uki_authenticode_sha384_edk2);
    assert.equal(candidate.references[0].digests.quoteSha256, native.quote_sha256);
    // Nothing in a candidate is a gateway-policy payload or signing input.
    assert.equal(candidate.schema, "anonrouter.gateway-policy-qualification-candidate/v1");
    for (const forbidden of ["payload", "signingBytes", "signatures", "sequence", "manifestSha256"]) assert.equal(forbidden in candidate, false);
    const posing = { schema: "anonrouter.gateway-policy-envelope/v1", payload: JSON.stringify(candidate), signatures: [] };
    assert.throws(() => verifySignedGatewayPolicy(posing, packagedGatewayPolicyAuthority(), SYNTHETIC.origin, NOW));
  });
  await test("a verdict file is never accepted in place of running native DCAP", async () => {
    const { check, gate } = await qualify({ reference: { dcapVerdict: "anything.json" } });
    assert.equal(check("native_dcap_verified").passed, false);
    assert.match(check("native_dcap_verified").detail, /not run/);
    assert.equal(gate("P1"), "satisfied"); assert.equal(gate("P2"), "unmet"); assert.equal(gate("P3"), "unmet");
  });
  await test("native DCAP refusals: out-of-date TCB and an engine that read a different TD", async () => {
    assert.equal((await qualify({}, { engine: "outofdate" })).check("native_dcap_verified").passed, false);
    const disagree = (await qualify({}, { engine: "disagree" })).check("native_dcap_verified");
    assert.equal(disagree.passed, false); assert.match(disagree.detail, /disagree about rtmr1/);
  });
  await test("firmware measured a different UKI than the release", async () => {
    const other = buildUki(GOOD_CMDLINE(SYNTHETIC.verityRoot).replace("panic=1", "panic=1 quiet"));
    const { check, gate } = await qualify({ ccel: encodeCcel(bootEvents(other)) }, { native: false });
    assert.equal(check("rtmr1_boot_application_is_uki").passed, false);
    assert.equal(check("ccel_events_classified").passed, false);
    assert.equal(gate("P1"), "unmet");
  });
  await test("the measured command line names another verity root", async () => {
    const { check } = await qualify({ uki: buildUki(GOOD_CMDLINE("6b".repeat(32))) }, { native: false });
    assert.equal(check("uki_cmdline_names_verity_root").passed, false);
  });
  await test("RTMR3 extended, owner register set, foreign boot key and wrong compose bytes", async () => {
    const extended = encodeCcel([...bootEvents(uki), selfDescribing(4, EV.EFI_ACTION, "runtime event")]);
    assert.equal((await qualify({ ccel: extended }, { native: false })).check("rtmr3_unextended").passed, false);
    assert.equal((await qualify({ quote: { mrOwner: "02".repeat(48) } }, { native: false })).check("owner_config_registers_zero").passed, false);
    assert.equal((await qualify({ binding: { instance_id: "ab".repeat(32) } }, { native: false })).check("instance_id_derives_from_boot_key").passed, false);
    const compose = await qualify({ compose: Buffer.from("{}\n"), tuple: {} }, { native: false });
    assert.equal(compose.check("compose_digest_matches_tuple").passed, false);
  });
  await test("the native cross-check compares digests, not its own verdict booleans", async () => {
    const lying = { ...native, gate_n1_uki_in_rtmr1: true, uki_authenticode_sha384_edk2: "00".repeat(48) };
    assert.equal((await qualify({}, { native: lying })).check("native_reference_digests_agree").passed, false);
  });
  await test("qualify-gcp refuses without the pilot acknowledgement or for another platform", async () => {
    const dir = mkdtempSync(join(root, "refusals-"));
    const { policy, bundle } = writeReferenceBoot(dir);
    await assert.rejects(qualifyGcpPolicyCandidate(policy, bundle, { baseDir: dir, nowMs: NOW }), /pilot/);
    await assert.rejects(qualifyGcpPolicyCandidate(policy, { ...bundle, references: [{ ...bundle.references[0], tupleId: "nope" }] },
      { unqualifiedPlatformPilot: true, baseDir: dir, nowMs: NOW }), /unknown tuple/);
    const phala = JSON.parse(readFileSync(new URL("../shared/vectors/gateway-release-tuples.json", import.meta.url), "utf8"))
      .loadCases.find(c => c.name === "phala tuple form").policy;
    await assert.rejects(qualifyGcpPolicyCandidate(phala, bundle, { unqualifiedPlatformPilot: true, baseDir: dir, nowMs: NOW }), /only gcp-tdx-native/);
    // And the signable preparation paths refuse the GCP policy outright.
    assert.throws(() => prepareGatewayPolicyRelease(Buffer.from("{}"), policy, 1, NOW, NOW + 1000));
    assert.throws(() => prepareTupleGatewayPolicyRelease([Buffer.from("{}")], policy, 1, NOW, NOW + 1000), /never signable/);
    assert.equal(loadGatewayPolicy(policy).platformKind, "gcp-tdx-native");
  });
  process.stdout.write(`GCP qualification tooling: ${passed} native-agreed KAT, CCEL/UKI and non-signable candidate groups passed.\n`);
} finally {
  rmSync(root, { recursive: true, force: true });
}
