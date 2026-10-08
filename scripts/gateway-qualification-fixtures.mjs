// SYNTHETIC, deterministic qualification artifacts for tests only. Nothing here
// is a Google firmware value, an AnonRouter release or an Intel-signed quote.
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { gatewayBindingHash } from "../js/confidential/dist/gateway/binding.js";
import { EV, replayCcel, parseCcel, authenticodeSha384Edk2 } from "./gateway-qualification.mjs";

const sha384 = data => createHash("sha384").update(data).digest();

/** A minimal PE32+ laid out at 512-byte file alignment, as a linker would. */
export function buildPe(sections, { trailing = Buffer.alloc(0), cert = null } = {}) {
  const ALIGN = 512, lfanew = 0x80, optSize = 240, table = lfanew + 24 + optSize;
  const headers = Math.ceil((table + 40 * sections.length) / ALIGN) * ALIGN;
  const head = Buffer.alloc(headers);
  head.write("MZ", 0, "latin1"); head.writeUInt32LE(lfanew, 0x3C); head.write("PE\0\0", lfanew, "latin1");
  const coff = lfanew + 4, opt = coff + 20;
  head.writeUInt16LE(0x8664, coff); head.writeUInt16LE(sections.length, coff + 2); head.writeUInt16LE(optSize, coff + 16);
  head.writeUInt16LE(0x20B, opt); head.writeUInt32LE(headers, opt + 60);
  head.writeUInt32LE(0xDEADBEEF, opt + 64); // checksum: excluded from the digest
  head.writeUInt32LE(16, opt + 108);
  const bodies = [];
  let pointer = headers, va = 0x1000;
  sections.forEach(([name, data], i) => {
    const raw = Math.ceil(data.length / ALIGN) * ALIGN, s = table + 40 * i;
    head.write(name, s, "latin1");
    head.writeUInt32LE(data.length, s + 8); head.writeUInt32LE(va, s + 12);
    head.writeUInt32LE(raw, s + 16); head.writeUInt32LE(pointer, s + 20);
    const body = Buffer.alloc(raw); Buffer.from(data).copy(body); bodies.push(body);
    pointer += raw; va += Math.ceil(Math.max(data.length, 1) / 0x1000) * 0x1000;
  });
  const certOffset = pointer + trailing.length;
  if (cert) { head.writeUInt32LE(certOffset, opt + 112 + 32); head.writeUInt32LE(cert.length, opt + 112 + 36); }
  return Buffer.concat([head, ...bodies, trailing, ...(cert ? [cert] : [])]);
}

export const GOOD_CMDLINE = (rootfsHash) => "console=ttyS0 init=/init panic=1 net.ifnames=0 random.trust_cpu=y "
  + `random.trust_bootloader=n tsc=reliable dstack.rootfs_hash=${rootfsHash} dstack.rootfs_size=8192`;

export function buildUki(cmdline, extra = {}) {
  return buildPe([[".osrel", Buffer.from("ID=synthetic\n")], [".cmdline", Buffer.from(`${cmdline}\0`)],
    [".initrd", Buffer.from("synthetic-cpio")], [".linux", Buffer.from("synthetic-bzimage")]], extra);
}

/** Encode a TCG crypto-agile CC event log with SHA-384 only. */
export function encodeCcel(events, fillTo = 4096) {
  const spec = Buffer.concat([Buffer.from("Spec ID Event03\0", "latin1"), Buffer.alloc(4), Buffer.from([0, 2, 0, 2]),
    u32(1), u16(0xC), u16(48), Buffer.from([0])]);
  const parts = [u32(0), u32(EV.NO_ACTION), Buffer.alloc(20), u32(spec.length), spec];
  for (const { mr, type, digest, data } of events) {
    parts.push(u32(mr), u32(type), u32(1), u16(0xC), digest, u32(data.length), data);
  }
  const out = Buffer.concat(parts);
  return out.length < fillTo ? Buffer.concat([out, Buffer.alloc(fillTo - out.length, 0xFF)]) : out;
}
function u32(v) { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; }
function u16(v) { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; }
export const selfDescribing = (mr, type, text) => { const data = Buffer.from(text); return { mr, type, digest: sha384(data), data }; };

/** The boot a well-behaved firmware would log: separators, the UKI, nothing else. */
export function bootEvents(uki) {
  return [
    selfDescribing(1, EV.EFI_ACTION, "synthetic firmware action"),
    selfDescribing(1, EV.SEPARATOR, "\0\0\0\0"),
    selfDescribing(2, EV.EFI_ACTION, "Calling EFI Application from Boot Option"),
    { mr: 2, type: EV.EFI_BOOT_SERVICES_APPLICATION, digest: Buffer.from(authenticodeSha384Edk2(uki), "hex"), data: Buffer.from("synthetic-device-path") },
    selfDescribing(3, EV.EFI_ACTION, "synthetic kernel command line handoff")
  ];
}

/** A structurally valid TDX v4 quote. No Intel signature. */
export function buildQuote({ reportData, mrTd, rtmr, tdAttributes, mrConfigId = "00".repeat(48), mrOwner = "00".repeat(48), mrOwnerConfig = "00".repeat(48) }) {
  const q = Buffer.alloc(632);
  q.writeUInt16LE(4, 0); q.writeUInt16LE(2, 2); q.writeUInt32LE(0x81, 4);
  Buffer.from(tdAttributes, "hex").copy(q, 168);
  Buffer.from(mrTd, "hex").copy(q, 184);
  Buffer.from(mrConfigId, "hex").copy(q, 232);
  Buffer.from(mrOwner, "hex").copy(q, 280);
  Buffer.from(mrOwnerConfig, "hex").copy(q, 328);
  rtmr.forEach((r, i) => Buffer.from(r, "hex").copy(q, 376 + 48 * i));
  Buffer.from(reportData, "hex").copy(q, 568);
  return q;
}

export const SYNTHETIC = Object.freeze({
  origin: "https://content.gcp.example", releaseId: "content@synthetic-a", verityRoot: "5a".repeat(32),
  mrTd: "1a".repeat(48), tdAttributes: "0000001000000000", bootKey: "e7".repeat(32), spki: "cc".repeat(32),
  nonce: "7".repeat(64), compose: Buffer.from('{"services":{"relay":{"image":"ghcr.io/example/relay@sha256:' + "1".repeat(64) + '"}}}\n')
});

/**
 * Write one complete reference boot plus a gcp policy and evidence bundle into
 * `dir`. `mutate` may change any artifact before it is written.
 */
export function writeReferenceBoot(dir, mutate = {}) {
  const composeHash = createHash("sha256").update(SYNTHETIC.compose).digest("hex");
  const uki = mutate.uki ?? buildUki(GOOD_CMDLINE(SYNTHETIC.verityRoot));
  const ccel = mutate.ccel ?? encodeCcel(bootEvents(uki));
  const rtmr = replayCcel(parseCcel(ccel));
  const binding = { v: 1, nonce: SYNTHETIC.nonce, app_id: SYNTHETIC.verityRoot,
    instance_id: createHash("sha256").update(Buffer.from(SYNTHETIC.bootKey, "hex")).digest("hex"), compose_hash: composeHash,
    release_id: SYNTHETIC.releaseId, origin: SYNTHETIC.origin, key_alg: "ed25519", public_key: SYNTHETIC.bootKey,
    transport: "in-tee-tls", tls_spki_sha256: SYNTHETIC.spki, ...mutate.binding };
  const quote = buildQuote({ reportData: gatewayBindingHash(binding), mrTd: SYNTHETIC.mrTd, rtmr,
    tdAttributes: SYNTHETIC.tdAttributes, ...mutate.quote });
  const tuple = { tupleId: "synthetic-a@c4-standard-2", releaseId: SYNTHETIC.releaseId, appId: SYNTHETIC.verityRoot,
    composeHash, mrTd: SYNTHETIC.mrTd, rtmr0: rtmr[0], rtmr1: rtmr[1], rtmr2: rtmr[2], tdAttributes: SYNTHETIC.tdAttributes,
    notBeforeMs: 1_791_000_000_000, expiresAtMs: 1_792_000_000_000, ...mutate.tuple };
  const policy = { platformKind: "gcp-tdx-native", source: "synthetic-gcp-qualification", version: "1", origins: [SYNTHETIC.origin],
    releaseTuples: [tuple], requireInTeeTls: true, requirePrivateLogs: true, requireDigestPinnedImages: true,
    requireHardwareVerified: true, acceptableTcbStatuses: ["UpToDate"], requireEvidenceExpiry: true, maxEvidenceAgeMs: 300_000 };
  writeFileSync(join(dir, "uki.efi"), uki);
  writeFileSync(join(dir, "ccel.bin"), ccel);
  writeFileSync(join(dir, "quote.bin"), quote);
  writeFileSync(join(dir, "compose.json"), mutate.compose ?? SYNTHETIC.compose);
  writeFileSync(join(dir, "collateral.json"), JSON.stringify({ synthetic: "not Intel collateral" }));
  writeFileSync(join(dir, "gateway-evidence.json"), JSON.stringify({ binding, quote: quote.toString("hex"), issued_at_ms: 1_791_327_000_000 }));
  const reference = { tupleId: tuple.tupleId, shape: "c4-standard-2", gatewayEvidence: "gateway-evidence.json", ccel: "ccel.bin",
    uki: "uki.efi", compose: "compose.json", collateral: "collateral.json", ...mutate.reference };
  const bundle = { schema: "anonrouter.gcp-qualification-evidence/v1", references: [reference] };
  writeFileSync(join(dir, "evidence.json"), JSON.stringify(bundle));
  return { policy, bundle, quote, uki, ccel, rtmr, tuple, binding };
}
