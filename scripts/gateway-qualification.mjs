// gcp-tdx-native qualification checks. Offline, read-only, Node only.
//
// This is an INDEPENDENT second implementation of the boot-chain semantics that
// the content guest's native `ar-guest-verify` applies, so a reviewer can see two
// codebases agree on the same bytes before any GCP tuple is trusted:
//
//   - the TDX CC event log (ACPI CCEL, TCG crypto-agile, SHA-384) is parsed
//     strictly and replayed into RTMR0..RTMR3;
//   - every extending event is classified: self-describing events must hash to
//     their own data, code events must be the release UKI or explicitly listed,
//     and RTMR1 must hold exactly one boot application;
//   - the UKI's EDK2 Authenticode SHA-384 (what firmware measures) is recomputed
//     from the PE bytes, and its measured .cmdline must name the release's
//     dm-verity root and carry no override or debug token.
//
// Nothing here trusts a boolean from another tool. Results are recomputed
// digests and the checks derived from them. Nothing here signs, publishes or
// reads a key, and nothing here can make a GCP policy acceptable to a client:
// GATEWAY_PLATFORM_QUALIFIED["gcp-tdx-native"] stays false in the SDK.

import { createHash } from "node:crypto";

export const sha = (alg, bytes) => createHash(alg).update(bytes).digest("hex");
const hex = bytes => Buffer.from(bytes).toString("hex");

export class QualificationError extends Error {
  constructor(code, detail) { super(`${code}: ${detail}`); this.name = "QualificationError"; this.code = code; }
}
const refuse = (code, detail) => { throw new QualificationError(code, detail); };
function u16(b, off) { if (off < 0 || off + 2 > b.length) refuse("truncated", `u16 at ${off}`); return b.readUInt16LE(off); }
function u32(b, off) { if (off < 0 || off + 4 > b.length) refuse("truncated", `u32 at ${off}`); return b.readUInt32LE(off); }
function slice(b, off, len) { if (off < 0 || len < 0 || off + len > b.length) refuse("truncated", `${len} bytes at ${off}`); return b.subarray(off, off + len); }

// ---- CC event log ------------------------------------------------------------

export const EV = Object.freeze({
  POST_CODE: 0x1, NO_ACTION: 0x3, SEPARATOR: 0x4, ACTION: 0x5, EVENT_TAG: 0x6, S_CRTM_CONTENTS: 0x7,
  S_CRTM_VERSION: 0x8, CPU_MICROCODE: 0x9, PLATFORM_CONFIG_FLAGS: 0xA, TABLE_OF_DEVICES: 0xB, COMPACT_HASH: 0xC,
  IPL: 0xD, NONHOST_CODE: 0xF, NONHOST_CONFIG: 0x10, NONHOST_INFO: 0x11, OMIT_BOOT_DEVICE_EVENTS: 0x12,
  EFI_VARIABLE_DRIVER_CONFIG: 0x80000001, EFI_VARIABLE_BOOT: 0x80000002, EFI_BOOT_SERVICES_APPLICATION: 0x80000003,
  EFI_BOOT_SERVICES_DRIVER: 0x80000004, EFI_RUNTIME_SERVICES_DRIVER: 0x80000005, EFI_GPT_EVENT: 0x80000006,
  EFI_ACTION: 0x80000007, EFI_PLATFORM_FIRMWARE_BLOB: 0x80000008, EFI_HANDOFF_TABLES: 0x80000009,
  EFI_PLATFORM_FIRMWARE_BLOB2: 0x8000000A, EFI_HANDOFF_TABLES2: 0x8000000B, EFI_VARIABLE_BOOT2: 0x8000000C,
  EFI_VARIABLE_AUTHORITY: 0x800000E0
});
const ALG = { SHA1: 0x4, SHA256: 0xB, SHA384: 0xC, SHA512: 0xD };
const KNOWN_DIGEST_SIZE = new Map([[ALG.SHA1, 20], [ALG.SHA256, 32], [ALG.SHA384, 48], [ALG.SHA512, 64]]);
const MAX_EVENTS = 4096;
const MAX_EVENT_DATA = 1 << 20;

/** Strict TCG crypto-agile parse. MR index 0 = MRTD, 1..4 = RTMR0..RTMR3. */
export function parseCcel(input) {
  const bytes = Buffer.from(input);
  if (u32(bytes, 4) !== EV.NO_ACTION) refuse("eventlog_header", "first record is not EV_NO_ACTION");
  const headerSize = u32(bytes, 28);
  const spec = slice(bytes, 32, headerSize);
  if (!slice(spec, 0, 16).equals(Buffer.from("Spec ID Event03\0", "latin1"))) refuse("eventlog_header", "missing Spec ID Event03");
  const count = u32(spec, 24);
  if (count === 0 || count > 8) refuse("eventlog_header", `${count} algorithms`);
  const algorithms = [];
  for (let i = 0; i < count; i++) {
    const alg = u16(spec, 28 + 4 * i), size = u16(spec, 30 + 4 * i);
    if (KNOWN_DIGEST_SIZE.has(alg) && KNOWN_DIGEST_SIZE.get(alg) !== size) refuse("eventlog_header", `alg ${alg} size ${size}`);
    algorithms.push([alg, size]);
  }
  if (!algorithms.some(([alg]) => alg === ALG.SHA384)) refuse("eventlog_no_sha384", "CC event logs must carry SHA-384");
  let off = 32 + headerSize;
  const events = [];
  for (;;) {
    if (off + 4 > bytes.length) break;
    const mrIndex = u32(bytes, off);
    // End of log: firmware fills the unused area with 0xFF (EDK2) or 0x00.
    if (mrIndex === 0xFFFFFFFF || (mrIndex === 0 && (off + 8 > bytes.length || u32(bytes, off + 4) === 0))) {
      const fill = bytes[off];
      if ((fill !== 0xFF && fill !== 0x00) || bytes.subarray(off).some(b => b !== fill)) refuse("eventlog_trailing", `non-fill bytes after end of log at ${off}`);
      break;
    }
    if (events.length >= MAX_EVENTS) refuse("eventlog_too_long", `more than ${MAX_EVENTS} events`);
    const start = off;
    const eventType = u32(bytes, off + 4);
    const digests = u32(bytes, off + 8);
    if (digests === 0 || digests > algorithms.length) refuse("eventlog_digest_count", `${digests} digests at ${start}`);
    off += 12;
    let sha384;
    for (let i = 0; i < digests; i++) {
      const alg = u16(bytes, off);
      const declared = algorithms.find(([a]) => a === alg);
      if (!declared) refuse("eventlog_alg", `undeclared alg ${alg} at ${start}`);
      const digest = slice(bytes, off + 2, declared[1]);
      if (alg === ALG.SHA384) {
        if (sha384) refuse("eventlog_digest_dup", `two SHA-384 digests at ${start}`);
        sha384 = hex(digest);
      }
      off += 2 + declared[1];
    }
    if (!sha384) refuse("eventlog_no_sha384", `event at ${start}`);
    const size = u32(bytes, off);
    if (size > MAX_EVENT_DATA) refuse("eventlog_event_size", `${size} bytes at ${start}`);
    const data = Buffer.from(slice(bytes, off + 4, size));
    off += 4 + size;
    if (mrIndex > 4) refuse("eventlog_mr_index", `index ${mrIndex} at ${start}`);
    events.push({ mrIndex, eventType, sha384, data, offset: start });
  }
  return { algorithms, events };
}

/** Replay extending records into RTMR0..RTMR3. An MRTD-index extend is refused. */
export function replayCcel(log) {
  const rtmr = [0, 1, 2, 3].map(() => Buffer.alloc(48));
  for (const e of log.events) {
    if (e.eventType === EV.NO_ACTION) continue;
    if (e.mrIndex < 1 || e.mrIndex > 4) refuse("eventlog_mr_index", `extend of index ${e.mrIndex} at ${e.offset}`);
    const i = e.mrIndex - 1;
    rtmr[i] = createHash("sha384").update(rtmr[i]).update(Buffer.from(e.sha384, "hex")).digest();
  }
  return rtmr.map(hex);
}

const SELF_DESCRIBING = new Set([EV.SEPARATOR, EV.ACTION, EV.EFI_ACTION, EV.EFI_GPT_EVENT, EV.S_CRTM_VERSION]);
const CODE = new Set([EV.EFI_BOOT_SERVICES_APPLICATION, EV.EFI_BOOT_SERVICES_DRIVER, EV.EFI_RUNTIME_SERVICES_DRIVER,
  EV.EFI_PLATFORM_FIRMWARE_BLOB, EV.EFI_PLATFORM_FIRMWARE_BLOB2, EV.POST_CODE, EV.S_CRTM_CONTENTS, EV.CPU_MICROCODE,
  EV.NONHOST_CODE]);
const CONFIG = new Set([EV.EFI_VARIABLE_DRIVER_CONFIG, EV.EFI_VARIABLE_BOOT, EV.EFI_VARIABLE_BOOT2,
  EV.EFI_VARIABLE_AUTHORITY, EV.EFI_HANDOFF_TABLES, EV.EFI_HANDOFF_TABLES2, EV.PLATFORM_CONFIG_FLAGS,
  EV.TABLE_OF_DEVICES, EV.NONHOST_CONFIG, EV.NONHOST_INFO, EV.OMIT_BOOT_DEVICE_EVENTS, EV.IPL, EV.EVENT_TAG,
  EV.COMPACT_HASH]);

/**
 * Classify every event. The RTMR chain covers digests, not event types, so a
 * log could relabel a code measurement as an action string; this layer is what
 * makes a replayed log mean something.
 */
export function classifyCcel(log, ukiSha384, allowedCode = []) {
  const findings = [], unlistedCode = [], rtmr1BootApplications = [];
  for (const e of log.events) {
    if (e.eventType === EV.NO_ACTION || CONFIG.has(e.eventType)) continue;
    if (SELF_DESCRIBING.has(e.eventType)) {
      if (sha("sha384", e.data) !== e.sha384) findings.push(`event at ${e.offset} type 0x${e.eventType.toString(16)} does not hash to its own data`);
    } else if (CODE.has(e.eventType)) {
      if (e.eventType === EV.EFI_BOOT_SERVICES_APPLICATION && e.mrIndex === 2) {
        rtmr1BootApplications.push(e.sha384);
        if (e.sha384 !== ukiSha384) findings.push(`RTMR1 boot application ${e.sha384} is not the release UKI`);
      } else if (!allowedCode.includes(e.sha384)) {
        unlistedCode.push(`unlisted code event 0x${e.eventType.toString(16)} in MR${e.mrIndex} at ${e.offset}: ${e.sha384}`);
      }
    } else {
      findings.push(`unknown event type 0x${e.eventType.toString(16)} at ${e.offset}`);
    }
  }
  if (rtmr1BootApplications.length !== 1) {
    findings.push(`RTMR1 contains ${rtmr1BootApplications.length} boot applications; exactly one (the UKI) is required`);
  }
  return { findings, unlistedCode, rtmr1BootApplications };
}

// ---- PE / Authenticode / UKI -------------------------------------------------

export function peLayout(input) {
  const pe = Buffer.from(input);
  if (pe.length < 2 || pe.toString("latin1", 0, 2) !== "MZ") refuse("pe_not_mz", "missing MZ header");
  const lfanew = u32(pe, 0x3C);
  if (!slice(pe, lfanew, 4).equals(Buffer.from("PE\0\0", "latin1"))) refuse("pe_signature", "missing PE signature");
  const coff = lfanew + 4;
  const sectionCount = u16(pe, coff + 2), optSize = u16(pe, coff + 16), opt = coff + 20;
  const magic = u16(pe, opt);
  const [dirCountOff, dirsOff] = magic === 0x20B ? [opt + 108, opt + 112] : magic === 0x10B ? [opt + 92, opt + 96]
    : refuse("pe_magic", `optional header magic 0x${magic.toString(16)}`);
  const dirCount = u32(pe, dirCountOff);
  const sizeOfHeaders = u32(pe, opt + 60);
  if (sizeOfHeaders > pe.length) refuse("pe_headers", "SizeOfHeaders beyond file");
  const checksumOff = opt + 64;
  let certDirOff = null, certTable = [0, 0];
  if (dirCount > 4) {
    certDirOff = dirsOff + 32;
    if (certDirOff + 8 > opt + optSize) refuse("pe_headers", "certificate directory outside optional header");
    certTable = [u32(pe, certDirOff), u32(pe, certDirOff + 4)];
  }
  if (checksumOff + 4 > sizeOfHeaders || (certDirOff !== null && certDirOff + 8 > sizeOfHeaders)) refuse("pe_headers", "excluded fields beyond SizeOfHeaders");
  const table = opt + optSize, sections = [];
  for (let i = 0; i < sectionCount; i++) {
    const s = table + 40 * i;
    sections.push({ name: slice(pe, s, 8).toString("latin1").replace(/\0+$/, ""), virtualSize: u32(pe, s + 8),
      sizeOfRawData: u32(pe, s + 16), pointerToRawData: u32(pe, s + 20) });
  }
  return { checksumOff, certDirOff, sizeOfHeaders, certTable, sections };
}

/** EDK2 MeasurePeImageAndExtend: the digest firmware extends into RTMR1. */
export function authenticodeSha384Edk2(input) {
  const pe = Buffer.from(input), l = peLayout(pe), h = createHash("sha384");
  h.update(pe.subarray(0, l.checksumOff));
  if (l.certDirOff !== null) {
    h.update(pe.subarray(l.checksumOff + 4, l.certDirOff));
    h.update(pe.subarray(l.certDirOff + 8, l.sizeOfHeaders));
  } else h.update(pe.subarray(l.checksumOff + 4, l.sizeOfHeaders));
  let sum = l.sizeOfHeaders;
  for (const s of l.sections.filter(s => s.sizeOfRawData > 0).sort((a, b) => a.pointerToRawData - b.pointerToRawData)) {
    const end = s.pointerToRawData + s.sizeOfRawData;
    if (end > pe.length) refuse("pe_section", `section ${s.name} beyond file`);
    h.update(pe.subarray(s.pointerToRawData, end));
    sum += s.sizeOfRawData;
  }
  if (pe.length > sum) {
    if (pe.length < sum + l.certTable[1]) refuse("pe_cert_table", "certificate table overlaps hashed data");
    h.update(pe.subarray(sum, pe.length - l.certTable[1]));
  }
  return h.digest("hex");
}

export function ukiSection(input, name) {
  const pe = Buffer.from(input);
  const matches = peLayout(pe).sections.filter(s => s.name === name);
  if (matches.length !== 1) refuse(matches.length ? "uki_section_duplicate" : "uki_section_missing", name);
  const s = matches[0];
  return slice(pe, s.pointerToRawData, Math.min(s.virtualSize, s.sizeOfRawData));
}

export function ukiCmdline(input) {
  const raw = ukiSection(input, ".cmdline");
  const nul = raw.indexOf(0);
  if (nul >= 0 && raw.subarray(nul).some(b => b !== 0)) refuse("uki_cmdline", "bytes after NUL terminator");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(nul >= 0 ? raw.subarray(0, nul) : raw);
  return text.replace(/\n+$/, "");
}

export function cmdlineValue(cmdline, key) {
  const values = cmdline.split(/\s+/).filter(t => t.startsWith(`${key}=`)).map(t => t.slice(key.length + 1));
  if (values.length !== 1) refuse(values.length ? "uki_cmdline_duplicate" : "uki_cmdline_missing", key);
  return values[0];
}

const REQUIRED_TOKENS = ["random.trust_cpu=y", "random.trust_bootloader=n", "init=/init", "panic=1"];
const FORBIDDEN_KEYS = new Set(["rd.break", "single", "emergency", "rescue", "systemd.debug_shell", "systemd.unit", "rdinit",
  "dstack.rootfs_device", "dstack.data_device", "debug", "nokaslr", "mitigations", "efi", "iommu", "swiotlb", "memmap",
  "kvm-intel.tdx"]);

/** Tokens that would let the host or a console step around the measured root. */
export function cmdlineFindings(cmdline) {
  const tokens = cmdline.split(/\s+/).filter(Boolean), findings = [];
  for (const required of REQUIRED_TOKENS) if (!tokens.includes(required)) findings.push(`missing required token ${required}`);
  for (const token of tokens) {
    const key = token.split("=")[0];
    if (FORBIDDEN_KEYS.has(key)) findings.push(`forbidden token ${token}`);
    if (key === "init" && token !== "init=/init") findings.push(`unexpected init ${token}`);
    if (key === "console" && token !== "console=ttyS0") findings.push(`unexpected console ${token}`);
  }
  return findings;
}

export function inspectUki(input) {
  for (const required of [".linux", ".initrd", ".cmdline"]) ukiSection(input, required);
  const cmdline = ukiCmdline(input);
  const rootfsHash = cmdlineValue(cmdline, "dstack.rootfs_hash");
  if (!/^[0-9a-f]{64}$/.test(rootfsHash)) refuse("uki_cmdline", "dstack.rootfs_hash is not 32 bytes of lowercase hex");
  const sizeText = cmdlineValue(cmdline, "dstack.rootfs_size");
  const rootfsSize = /^[1-9][0-9]{0,15}$/.test(sizeText) ? Number(sizeText) : 0;
  if (!Number.isSafeInteger(rootfsSize) || rootfsSize === 0 || rootfsSize % 4096 !== 0) refuse("uki_cmdline", "dstack.rootfs_size is not a positive multiple of 4096");
  return { authenticodeSha384: authenticodeSha384Edk2(input), fileSha256: sha("sha256", input), cmdline,
    rootfsHash, rootfsSize, cmdlineFindings: cmdlineFindings(cmdline), sections: peLayout(input).sections.map(s => s.name) };
}
