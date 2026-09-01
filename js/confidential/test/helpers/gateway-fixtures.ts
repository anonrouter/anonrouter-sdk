// Synthetic Intel TDX quote + dstack event log builder for the gateway
// attestation tests. This fabricates the STRUCTURE of a quote (byte offsets,
// registers, report_data) so the verifier's structural, replay, binding, and
// policy logic can be exercised deterministically without TDX hardware.
//
// It deliberately cannot fabricate a valid Intel ECDSA signature. That is the
// point: tests using this fixture must never assert `hardware-verified`, only
// `provider-attested`, which is exactly the honest ceiling the real verifier
// applies when no DCAP chain verifier is wired.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8Encode } from "../../src/bytes.js";
import {
  computeRtmr3EventDigestV1,
  replayRegister,
  rtmr3EventDigest,
  type DstackEventLogEntry
} from "../../src/gateway/eventLog.js";
import { sha384Hex } from "./sha384.js";

const HEADER_LEN = 48;
const BODY_LEN = 584;
export const TEE_TYPE_TDX = 0x00000081;

// Offsets from the start of the quote, mirroring src/verify/tdx.ts.
const OFF_TD_ATTRIBUTES = 168;
const OFF_MR_TD = 184;
const OFF_MR_CONFIG_ID = 232;
const OFF_RTMR0 = 376;
const OFF_REPORT_DATA = 568;

/**
 * Shape of MRCONFIGID as observed on the production TDX CVM: a 33-byte
 * compressed SEC1 point, zero-padded to 48. Hard-coded here so a test that pins
 * it is exercising the real field layout rather than a convenient zero.
 */
export const SYNTHETIC_MR_CONFIG_ID = "02" + "ab".repeat(32) + "00".repeat(15);

/** The dstack OS image hash the synthetic event log measures. */
export const SYNTHETIC_OS_IMAGE_HASH = "de".repeat(32);

export interface SyntheticQuoteOptions {
  reportDataHex: string;
  rtmr0?: string;
  rtmr1?: string;
  rtmr2?: string;
  rtmr3?: string;
  mrTd?: string;
  mrConfigId?: string;
  teeType?: number;
  debug?: boolean;
}

const ZERO_48 = "0".repeat(96);

/** Build a structurally valid TDX v4 quote with the given measurements. */
export function buildSyntheticTdxQuote(options: SyntheticQuoteOptions): string {
  const buf = new Uint8Array(HEADER_LEN + BODY_LEN);
  const view = new DataView(buf.buffer);
  view.setUint16(0, 4, true); // version
  view.setUint16(2, 2, true); // att_key_type (ECDSA-P256)
  view.setUint32(4, options.teeType ?? TEE_TYPE_TDX, true);

  if (options.debug) buf[OFF_TD_ATTRIBUTES] |= 0x01;

  const write = (offset: number, hex: string, bytes: number) => {
    const value = hexToBytes(hex);
    if (value.length !== bytes) throw new Error(`expected ${bytes} bytes at offset ${offset}`);
    buf.set(value, offset);
  };

  write(OFF_MR_TD, options.mrTd ?? ZERO_48, 48);
  write(OFF_MR_CONFIG_ID, options.mrConfigId ?? SYNTHETIC_MR_CONFIG_ID, 48);
  write(OFF_RTMR0, options.rtmr0 ?? ZERO_48, 48);
  write(OFF_RTMR0 + 48, options.rtmr1 ?? ZERO_48, 48);
  write(OFF_RTMR0 + 96, options.rtmr2 ?? ZERO_48, 48);
  write(OFF_RTMR0 + 144, options.rtmr3 ?? ZERO_48, 48);
  write(OFF_REPORT_DATA, options.reportDataHex, 64);

  return bytesToHex(buf);
}

/** Read one 48-byte register back out of a synthetic quote, for pinning tests. */
export function quoteRegister(quoteHex: string, offset: number): string {
  return quoteHex.slice(offset * 2, (offset + 48) * 2);
}

export const QUOTE_OFFSETS = {
  mrTd: OFF_MR_TD,
  mrConfigId: OFF_MR_CONFIG_ID,
  rtmr0: OFF_RTMR0,
  rtmr1: OFF_RTMR0 + 48,
  rtmr2: OFF_RTMR0 + 96
} as const;

export const DSTACK_EVENT_TYPE = 134_217_729;

/**
 * A dstack V1 RTMR3 event.
 *
 * `digest` is left EMPTY, matching what a real guest agent returns (observed on
 * dstack 0.5.9 / guest agent 0.5.7): RTMR3 entries ship without a digest and the
 * verifier derives it from (event_type, event, event_payload).
 */
export function rtmr3Event(event: string, payloadHex: string, eventType = DSTACK_EVENT_TYPE): DstackEventLogEntry {
  return { imr: 3, event_type: eventType, digest: "", event, event_payload: payloadHex };
}

/** The same event, additionally carrying the digest it derives to. */
export function rtmr3EventWithDigest(
  event: string,
  payloadHex: string,
  eventType = DSTACK_EVENT_TYPE
): DstackEventLogEntry {
  const entry = rtmr3Event(event, payloadHex, eventType);
  return { ...entry, digest: computeRtmr3EventDigestV1(entry) };
}

/**
 * A dstack V2 RTMR3 event: the hashed bytes are published as `preimage` and the
 * digest is SHA-384 over them. Real CVMs emit this form, so the verifier must
 * accept it without falling back to the V1 concatenation.
 */
export function rtmr3EventV2(
  event: string,
  payloadHex: string,
  eventType = DSTACK_EVENT_TYPE
): DstackEventLogEntry {
  // Canonical JSON with sorted keys, matching dstack's JCS serialization.
  const preimageBytes = utf8Encode(JSON.stringify({ name: event, payload: payloadHex, type: eventType }));
  return {
    imr: 3,
    event_type: eventType,
    digest: sha384Hex(preimageBytes),
    event,
    event_payload: payloadHex,
    preimage: bytesToHex(preimageBytes),
    version: 2
  };
}

/** A boot-chain event for RTMR0..2, whose digest is opaque firmware output. */
export function bootEvent(imr: number, seed: string): DstackEventLogEntry {
  return {
    imr,
    event_type: 2_147_483_659,
    digest: sha384Hex(utf8Encode(seed)),
    event: "",
    event_payload: ""
  };
}

export interface SyntheticEvidenceEventLog {
  events: DstackEventLogEntry[];
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
}

/**
 * Build a complete event log for a dstack CVM and the RTMR values it replays to,
 * so a caller can construct a quote whose registers match the log.
 */
export function buildSyntheticEventLog(options: {
  appId: string;
  composeHash: string;
  instanceId: string;
  keyProviderId?: string;
  osImageHash?: string;
  extraRtmr3?: DstackEventLogEntry[];
}): SyntheticEvidenceEventLog {
  // Event order mirrors a real dstack 0.5.9 boot, so a test that depends on
  // ordering is depending on the same ordering production has.
  const events: DstackEventLogEntry[] = [
    bootEvent(0, "virtual-firmware"),
    bootEvent(1, "kernel"),
    bootEvent(2, "kernel-cmdline"),
    rtmr3Event("system-preparing", ""),
    rtmr3Event("app-id", options.appId),
    rtmr3Event("compose-hash", options.composeHash),
    rtmr3Event("instance-id", options.instanceId),
    rtmr3Event("os-image-hash", options.osImageHash ?? SYNTHETIC_OS_IMAGE_HASH),
    rtmr3Event(
      "key-provider",
      bytesToHex(utf8Encode(JSON.stringify({ name: "kms", id: options.keyProviderId ?? "0".repeat(64) })))
    ),
    ...(options.extraRtmr3 ?? [])
  ];
  // RTMR3 replays from DERIVED digests, exactly as the verifier does, because the
  // real agent ships those entries without one.
  const registerFor = (imr: number) => replayRegister(events
    .filter((e) => e.imr === imr)
    .map((e) => (imr === 3 ? rtmr3EventDigest(e) ?? "ff".repeat(48) : e.digest)));
  return {
    events,
    rtmr0: registerFor(0),
    rtmr1: registerFor(1),
    rtmr2: registerFor(2),
    rtmr3: registerFor(3)
  };
}

/**
 * The vm_config blob a CVM serves, as a JSON string. Only `os_image_hash` is
 * load-bearing for the verifier: it is cross-checked against the measured
 * `os-image-hash` event so a served vm_config cannot send an auditor to reproduce
 * measurements for a different OS image.
 */
export function buildVmConfig(osImageHash = SYNTHETIC_OS_IMAGE_HASH): string {
  return JSON.stringify({
    os_image_hash: osImageHash,
    cpu_count: 1,
    memory_size: 2_147_483_648,
    spec_version: 1
  });
}

/** Build the `app_compose` manifest string and its measured SHA-256. */
export function buildAppCompose(overrides: Record<string, unknown> = {}): { manifest: string; hash: string } {
  const dockerCompose = [
    "services:",
    "  relay:",
    "    image: ghcr.io/example/anonrouter@sha256:" + "1".repeat(64),
    "    read_only: true",
    "  gateway-attestation:",
    "    image: ghcr.io/example/anonrouter@sha256:" + "2".repeat(64)
  ].join("\n");
  const manifest = JSON.stringify({
    manifest_version: 2,
    name: "anonrouter-tee",
    runner: "docker-compose",
    docker_compose_file: dockerCompose,
    public_logs: false,
    public_sysinfo: false,
    kms_enabled: true,
    gateway_enabled: true,
    ...overrides
  });
  return { manifest, hash: bytesToHex(sha256(utf8Encode(manifest))) };
}
