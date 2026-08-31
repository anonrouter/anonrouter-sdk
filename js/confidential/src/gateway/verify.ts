// Independent, fail-closed verification of AnonRouter GATEWAY attestation.
//
// This is the client side of GET /v1/gateway/attestation, the hop that answers
// "is the AnonRouter data plane I am talking to the exact reviewed build running
// inside an Intel TDX confidential VM?". The provider verifiers in ../verify/*
// answer the other hop. Neither implies the other, which is why they are separate
// modules with separate verdicts.
//
// It is deliberately pure: no network, no filesystem, no clock except an injected
// `now`, and no dependency on any vendor SDK. Everything it needs to reach a
// verdict is either in the evidence document, in the locally pinned policy, or
// recomputed from first principles here.
//
// The chain it establishes, in order:
//
//   1. The quote is a structurally valid, non-debug Intel TDX quote.
//   2. Its 64-byte report_data equals SHA-512 of the canonical binding object, so
//      the TD asserted the caller's nonce, the app/instance identity, the compose
//      measurement, the release id, the origin, the application key, and the
//      transport claim, all at once, at quote time.
//   3. The plaintext event log replays to the quote's RTMR0..RTMR3, so the log
//      describes what the hardware actually measured.
//   4. The measured "compose-hash" event equals SHA-256 of the returned
//      app-compose manifest, so the manifest is the one that ran.
//   5. The manifest's own contents satisfy the pinned policy: private logs,
//      digest-pinned images.
//   6. The app id, compose hash, release id, and origin are all on the locally
//      pinned allowlist.
//   7. Optionally, the TD owns the TLS certificate the caller is using.
//
// What this module does NOT do on its own is chain the quote's ECDSA signature to
// Intel's roots. That requires DCAP collateral, which this package deliberately
// does not ship, so it is injected through the pluggable TdxChainVerifier port.
// Without one the honest verdict is `provider-attested`, never
// `hardware-verified`. This SDK does not upgrade a claim it did not check.

import { hexToBytes, utf8DecodeLossy } from "../bytes.js";
import { check } from "../verify/checks.js";
import { hexEqual } from "../verify/crypto.js";
import { parseTdxQuote, TDX_TEE_TYPE } from "../verify/tdx.js";
import type { AttestationCheck, VerificationLevel } from "../verify/types.js";
import {
  canonicalGatewayOrigin,
  gatewayBindingHash,
  normalizeGatewayBinding,
  type GatewayAttestationBinding
} from "./binding.js";
import { readAttestedAppCompose, type AttestedAppCompose } from "./appCompose.js";
import { inconsistentRtmr3Events, parseEventLog, replayRtmrs, singleEventPayload } from "./eventLog.js";
import type { GatewayMeasurementPolicy } from "./policy.js";

/** A vm_config blob is bounded so a hostile response cannot pin the CPU parsing it. */
const MAX_VM_CONFIG_CHARS = 65_536;

/** What a chain verifier reports back about one quote. */
export interface TdxChainOutcome {
  verified: boolean;
  /** The platform's TCB status, when the engine reported one. */
  tcbStatus?: string;
  /**
   * Content-free explanation, carried into the check's detail so a refusal names
   * itself. Never include the quote, collateral, or any caller input.
   */
  detail?: string;
}

/**
 * The pluggable port for chaining a TDX quote's ECDSA signature to Intel's roots.
 *
 * This package ships no engine (see gateway/dcap for why, and for the official
 * adapter to the reviewed one). Supply an implementation to reach
 * `hardware-verified`; supply none and a policy demanding it fails closed.
 *
 * Deliberately SYNCHRONOUS, because `verifyGatewayAttestation` is pure and
 * synchronous. Anything that needs I/O (a subprocess, a network call, collateral)
 * runs in a `TdxChainVerifierFactory.prepare()` first, and hands the finished
 * verdict in bound to the exact quote it ran on.
 */
export interface TdxChainVerifier {
  /** Free-form name of the engine, carried into the verdict for the audit trail. */
  readonly implementation: string;
  verifyChain(quote: string, collateral?: unknown): TdxChainOutcome;
}

/** What the caller knows at prepare time and the engine should be told. */
export interface TdxChainVerifierContext {
  /**
   * The TCB statuses the resolved policy accepts.
   *
   * Passed through so the engine and the local policy cannot disagree about what
   * "acceptable" means. An engine gating on `UpToDate` while the policy also
   * accepts `SWHardeningNeeded` would refuse quotes the policy allows, and the
   * reverse would be worse.
   */
  acceptedTcbStatuses?: readonly string[];
  /** The verification time the caller will use, epoch ms. */
  nowMs?: number;
  signal?: AbortSignal;
}

/**
 * An engine that needs I/O before it can answer.
 *
 * `prepare()` does the work (spawn, fetch collateral, call a service) and returns
 * a verifier bound to that one quote. A prepared verifier refuses any other
 * quote, so one quote's pass can never be replayed onto another.
 */
export interface TdxChainVerifierFactory {
  prepare(quote: string, context?: TdxChainVerifierContext): Promise<TdxChainVerifier>;
}

/**
 * Read `os_image_hash` out of the served vm_config blob, which arrives as a JSON
 * string (dstack serves it verbatim so its bytes can be re-fed to dstack-mr).
 * Returns null for anything unusable, so the caller records a visible gap rather
 * than treating absence as agreement.
 */
function readVmConfigOsImageHash(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_VM_CONFIG_CHARS) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const value = (parsed as Record<string, unknown>).os_image_hash;
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase().replace(/^0x/, "");
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

/** The evidence document returned by GET /v1/gateway/attestation. */
export interface GatewayAttestationEvidence {
  /** The exact object the TD hashed into report_data. */
  binding: unknown;
  /** Raw Intel TDX quote (hex or base64). */
  quote: string;
  /** Event log as a JSON string or an already-parsed array. */
  event_log: unknown;
  /** The measured app-compose manifest string (tcb_info.app_compose). */
  app_compose: unknown;
  /** Wall-clock time the gateway produced this document, epoch ms. */
  issued_at_ms?: unknown;
  /** VM configuration blob, passed through for independent inspection. */
  vm_config?: unknown;
}

export interface GatewayVerificationExpectations {
  /** The exact nonce this client generated and sent. */
  nonce: string;
  /** The exact origin this client connected to. */
  origin: string;
  /** Locally pinned policy. NEVER fetched from the gateway. */
  policy: GatewayMeasurementPolicy;
  /** Injected clock so verification stays pure and testable. */
  now: number;
  /**
   * SHA-256 of the DER SubjectPublicKeyInfo of the certificate this client's TLS
   * session actually used. Supply it to prove the attested TD owns the very
   * connection carrying the request. Undefined means "not observed" (a browser
   * cannot see it); null means "observed and there is none".
   */
  observedTlsSpkiSha256?: string | null;
  /** Optional DCAP chain verifier. Absent means no hardware-verified verdict. */
  chainVerifier?: TdxChainVerifier;
}

export interface GatewayVerificationResult {
  status: "ok" | "failed";
  verificationLevel: VerificationLevel;
  checks: AttestationCheck[];
  /** The first failed required check, or null. Sanitized and content-free. */
  reason: string | null;
  /** Normalized binding, present whenever it parsed. */
  binding: GatewayAttestationBinding | null;
  /** Parsed manifest facts, present whenever the manifest parsed. */
  appCompose: AttestedAppCompose | null;
  /** Measurements read out of the quote, for display and audit. */
  measurements: {
    mrTd: string;
    mrConfigId: string;
    rtmr0: string;
    rtmr1: string;
    rtmr2: string;
    rtmr3: string;
  } | null;
  /** TCB status reported by the chain verifier, when one ran. */
  tcbStatus: string | null;
  policySource: string;
  policyVersion: string;
  verifiedAtMs: number;
}

function failed(
  checks: AttestationCheck[],
  policy: GatewayMeasurementPolicy,
  now: number,
  partial: Partial<GatewayVerificationResult> = {}
): GatewayVerificationResult {
  const firstFailure = checks.find((entry) => entry.required && !entry.passed);
  return {
    status: "failed",
    verificationLevel: "unverified",
    checks,
    reason: firstFailure?.name ?? "verification_failed",
    binding: null,
    appCompose: null,
    measurements: null,
    tcbStatus: null,
    policySource: policy.source,
    policyVersion: policy.version,
    verifiedAtMs: now,
    ...partial
  };
}

/**
 * Verify a gateway attestation document. Never throws on hostile input: every
 * malformed field becomes a failed required check, so a caller that only reads
 * `status` cannot be tricked by an exception path.
 */
export function verifyGatewayAttestation(
  evidence: GatewayAttestationEvidence,
  expectations: GatewayVerificationExpectations
): GatewayVerificationResult {
  const { policy, now } = expectations;
  const checks: AttestationCheck[] = [];

  // --- 1. Binding -----------------------------------------------------------
  let binding: GatewayAttestationBinding;
  try {
    binding = normalizeGatewayBinding(evidence?.binding);
    checks.push(check("binding_wellformed", true, true));
  } catch (error) {
    checks.push(check("binding_wellformed", false, true, error instanceof Error ? error.message : undefined));
    return failed(checks, policy, now);
  }

  // --- 2. Quote structure ---------------------------------------------------
  const quote = parseTdxQuote(evidence.quote);
  checks.push(check("quote_parsed", quote !== null, true));
  if (!quote) return failed(checks, policy, now, { binding });

  checks.push(check("quote_is_tdx", quote.teeType === TDX_TEE_TYPE, true, `tee_type=0x${quote.teeType.toString(16)}`));
  // A debug TD lets the host inspect and modify guest memory. Nothing measured
  // inside it is confidential, so this is unconditionally fatal.
  checks.push(check("quote_not_debug", !quote.debugEnabled, true));

  const measurements = {
    mrTd: quote.mrTd,
    mrConfigId: quote.mrConfigId,
    rtmr0: quote.rtmr0,
    rtmr1: quote.rtmr1,
    rtmr2: quote.rtmr2,
    rtmr3: quote.rtmr3
  };

  // --- 3. report_data commits to the whole binding --------------------------
  let bindingHash: string;
  try {
    bindingHash = gatewayBindingHash(binding);
  } catch (error) {
    checks.push(check("binding_hash_computed", false, true, error instanceof Error ? error.message : undefined));
    return failed(checks, policy, now, { binding, measurements });
  }
  checks.push(check("report_data_binds_binding", hexEqual(quote.reportData, bindingHash), true));

  // --- 4. Freshness and origin, checked against what THIS client did --------
  let expectedOrigin: string | null = null;
  try {
    expectedOrigin = canonicalGatewayOrigin(expectations.origin);
  } catch {
    expectedOrigin = null;
  }
  checks.push(check("nonce_matches_request", binding.nonce === expectations.nonce.toLowerCase(), true));
  checks.push(check("origin_matches_connection", expectedOrigin !== null && binding.origin === expectedOrigin, true));

  // --- 5. Event log replays to the quote's registers ------------------------
  let composeHashEvent: string | null = null;
  let instanceIdEvent: string | null = null;
  let appIdEvent: string | null = null;
  let keyProviderEvent: string | null = null;
  let osImageHashEvent: string | null = null;
  let eventLogRead = false;
  try {
    const events = parseEventLog(evidence.event_log);
    const replayed = replayRtmrs(events);
    const replays = hexEqual(replayed[0], quote.rtmr0)
      && hexEqual(replayed[1], quote.rtmr1)
      && hexEqual(replayed[2], quote.rtmr2)
      && hexEqual(replayed[3], quote.rtmr3);
    checks.push(check("event_log_replays_rtmrs", replays, true));

    // Replay alone proves only that the DIGESTS are the measured ones. Each RTMR3
    // digest must additionally commit to the human-readable name and payload
    // printed beside it, or a genuine quote could be re-served with a rewritten
    // compose-hash payload and still replay correctly.
    const inconsistent = inconsistentRtmr3Events(events);
    checks.push(check(
      "event_digests_commit_to_payloads",
      inconsistent.length === 0,
      true,
      inconsistent.length > 0 ? `${inconsistent.length} RTMR3 event(s) with a non-committing digest` : undefined
    ));

    composeHashEvent = singleEventPayload(events, "compose-hash");
    instanceIdEvent = singleEventPayload(events, "instance-id");
    appIdEvent = singleEventPayload(events, "app-id");
    keyProviderEvent = singleEventPayload(events, "key-provider");
    osImageHashEvent = singleEventPayload(events, "os-image-hash");
    eventLogRead = true;
  } catch (error) {
    const detail = error instanceof Error ? error.message : undefined;
    checks.push(check("event_log_replays_rtmrs", false, true, detail));
    checks.push(check("event_digests_commit_to_payloads", false, true, detail));
  }

  // The compose hash the TD asserted in the binding must be the one hardware
  // measured. Without this the binding could name any configuration it liked.
  checks.push(check(
    "compose_hash_measured_in_rtmr3",
    composeHashEvent !== null && hexEqual(composeHashEvent, binding.compose_hash),
    true
  ));
  // instance-id is measured too; when present it must agree with the binding.
  // "Absent" is only acceptable when the log was actually readable, otherwise an
  // unparsable log would silently satisfy this check.
  checks.push(check(
    "instance_id_measured",
    eventLogRead && (instanceIdEvent === null || hexEqual(instanceIdEvent, binding.instance_id)),
    true,
    instanceIdEvent === null ? "no instance-id event in log" : undefined
  ));
  // app-id is measured independently of the binding, so a TD cannot claim an app
  // identity it was not provisioned with.
  checks.push(check(
    "app_id_measured",
    eventLogRead && appIdEvent !== null && hexEqual(appIdEvent, binding.app_id),
    true
  ));
  // key-provider names who may hold this app's derived keys. A CVM booted under a
  // different key provider is a different trust domain even at the same compose
  // hash, so this is pinned rather than merely reported.
  if (policy.keyProviderId) {
    const expected = policy.keyProviderId.toLowerCase();
    // The payload is a JSON blob ({"name":"kms","id":"<k256 pubkey>"}) encoded as
    // hex, so match on the decoded text rather than the whole-field digest.
    const decoded = keyProviderEvent === null
      ? ""
      : utf8DecodeLossy(hexToBytes(keyProviderEvent)).toLowerCase();
    checks.push(check("key_provider_pinned", decoded.includes(expected), true));
  } else {
    checks.push(check(
      "key_provider_pinned",
      false,
      false,
      "policy pins no key provider; a CVM under a different KMS would still pass"
    ));
  }

  // vm_config is what lets someone recompute MRTD and RTMR0..2 offline with
  // dstack-mr. It is served by the CVM, so on its own it is a claim; it becomes
  // evidence only once it agrees with something hardware measured. The measured
  // `os-image-hash` event is that anchor. A CVM that serves a vm_config naming a
  // different OS image than the one it booted would otherwise send an auditor to
  // reproduce the wrong measurements and conclude the quote was forged.
  const vmConfigOsImage = readVmConfigOsImageHash(evidence.vm_config);
  if (osImageHashEvent !== null && vmConfigOsImage !== null) {
    checks.push(check(
      "vm_config_matches_measured_os_image",
      hexEqual(osImageHashEvent, vmConfigOsImage),
      true
    ));
  } else {
    checks.push(check(
      "vm_config_matches_measured_os_image",
      false,
      false,
      osImageHashEvent === null
        ? "no os-image-hash event in the log to anchor vm_config against"
        : "evidence carries no vm_config.os_image_hash, so offline measurement recomputation is unanchored"
    ));
  }

  // --- 6. The manifest is the measured one, and says what it should ---------
  let appCompose: AttestedAppCompose | null = null;
  try {
    appCompose = readAttestedAppCompose(evidence.app_compose);
    checks.push(check("app_compose_parsed", true, true));
  } catch (error) {
    checks.push(check("app_compose_parsed", false, true, error instanceof Error ? error.message : undefined));
  }
  checks.push(check(
    "app_compose_matches_measurement",
    appCompose !== null && hexEqual(appCompose.composeHash, binding.compose_hash),
    true
  ));

  if (policy.requirePrivateLogs) {
    checks.push(check(
      "compose_public_logs_disabled",
      appCompose?.publicLogs === false,
      true,
      appCompose ? `public_logs=${String(appCompose.publicLogs)}` : undefined
    ));
  }
  if (policy.requireDigestPinnedImages) {
    const unpinned = appCompose?.images.filter((image) => !image.digestPinned) ?? [];
    checks.push(check(
      "compose_images_digest_pinned",
      appCompose !== null && appCompose.images.length > 0 && unpinned.length === 0,
      true,
      unpinned.length > 0 ? `${unpinned.length} image reference(s) not digest-pinned` : undefined
    ));
  }

  // --- 7. Locally pinned identity -------------------------------------------
  checks.push(check("app_id_pinned", policy.appIds.some((id) => hexEqual(id, binding.app_id)), true));
  checks.push(check(
    "compose_hash_pinned",
    policy.composeHashes.some((hash) => hexEqual(hash, binding.compose_hash)),
    true
  ));
  checks.push(check("release_pinned", policy.releaseIds.includes(binding.release_id), true));
  checks.push(check("origin_pinned", policy.origins.includes(binding.origin), true));

  if (policy.platform) {
    const { mrTd, mrConfigId, rtmr0, rtmr1, rtmr2, osImageHash } = policy.platform;
    checks.push(check(
      "platform_measurements_pinned",
      mrTd.some((value) => hexEqual(value, quote.mrTd))
      && mrConfigId.some((value) => hexEqual(value, quote.mrConfigId))
      && rtmr0.some((value) => hexEqual(value, quote.rtmr0))
      && rtmr1.some((value) => hexEqual(value, quote.rtmr1))
      && rtmr2.some((value) => hexEqual(value, quote.rtmr2)),
      true
    ));
    // Pinned separately from the registers above because it is the one platform
    // value an operator can read off a release note and compare by eye.
    checks.push(check(
      "os_image_pinned",
      osImageHashEvent !== null && osImageHash.some((value) => hexEqual(value, osImageHashEvent)),
      true,
      osImageHashEvent === null ? "no os-image-hash event in the log" : undefined
    ));
  }

  // --- 8. Transport binding --------------------------------------------------
  if (policy.requireInTeeTls) {
    checks.push(check("transport_terminates_in_tee", binding.transport === "in-tee-tls", true));
    if (expectations.observedTlsSpkiSha256 !== undefined) {
      checks.push(check(
        "tls_certificate_bound_to_quote",
        hexEqual(expectations.observedTlsSpkiSha256, binding.tls_spki_sha256),
        true
      ));
    } else {
      // Advisory: the caller could not observe its own certificate (a browser
      // cannot). Recorded so the gap is visible rather than assumed away.
      checks.push(check("tls_certificate_bound_to_quote", false, false, "caller did not observe its TLS certificate"));
    }
  } else {
    checks.push(check(
      "transport_terminates_in_tee",
      binding.transport === "in-tee-tls",
      false,
      binding.transport === "gateway-tls" ? "TLS terminates at the platform gateway, not inside the TD" : undefined
    ));
  }

  // --- 9. Evidence expiry ----------------------------------------------------
  // The nonce is the primary anti-replay proof, so this is defence in depth. It
  // is required only when the policy says so, but note WHY the "no timestamp"
  // case fails rather than passing: a document that cannot be aged has not been
  // shown to be fresh, and treating unmeasurable as acceptable is how an expiry
  // check quietly stops existing.
  const issuedAt = typeof evidence.issued_at_ms === "number" ? evidence.issued_at_ms : null;
  const age = issuedAt === null ? null : now - issuedAt;
  checks.push(check(
    "evidence_recent",
    age !== null && age >= -60_000 && age <= policy.maxEvidenceAgeMs,
    policy.requireEvidenceExpiry,
    age === null ? "no issued_at_ms" : `age_ms=${age}`
  ));

  // --- 10. Hardware chain (pluggable) ---------------------------------------
  let tcbStatus: string | null = null;
  let chainVerified = false;
  if (expectations.chainVerifier) {
    const outcome = expectations.chainVerifier.verifyChain(evidence.quote, undefined);
    tcbStatus = outcome.tcbStatus ?? null;
    // The TCB status is enforced against the policy EVEN WHEN the verifier said
    // verified. A quote can chain perfectly to Intel's roots while the platform
    // holding your data has known unpatched vulnerabilities, and an engine's own
    // idea of an acceptable status is not this policy's decision to delegate.
    const tcbAcceptable = tcbStatus === null
      ? false
      : policy.acceptableTcbStatuses.some((status) => status.toLowerCase() === tcbStatus!.toLowerCase());
    chainVerified = outcome.verified && tcbAcceptable;
    checks.push(check(
      "quote_signature_chain",
      outcome.verified,
      true,
      // The engine's own reason first: "engine binary not found" and "the
      // signature is invalid" are very different problems and a bare
      // "no TCB status" would hide which one a reader is looking at.
      outcome.detail ?? (tcbStatus ? `tcb=${tcbStatus}` : "chain verifier reported no TCB status")
    ));
    checks.push(check(
      "tcb_status_acceptable",
      tcbAcceptable,
      true,
      tcbStatus === null
        ? "chain verifier returned no TCB status, so it cannot be checked against the policy"
        : `tcb=${tcbStatus}, accepted=${policy.acceptableTcbStatuses.join("|")}`
    ));
  } else {
    // Required when the policy demands hardware verification, so a client whose
    // DCAP engine is missing or unbuilt fails loudly instead of quietly accepting
    // at the weaker level and reporting success.
    checks.push(check(
      "quote_signature_chain",
      false,
      policy.requireHardwareVerified,
      policy.requireHardwareVerified
        ? "policy requires hardware verification but no DCAP chain verifier was supplied"
        : "no DCAP chain verifier supplied; verdict capped at provider-attested"
    ));
    // Recorded even with no verifier, so the check set is the same shape either
    // way and a reader diffing two verdicts is not left wondering whether the
    // TCB was checked and passed or never looked at.
    checks.push(check(
      "tcb_status_acceptable",
      false,
      policy.requireHardwareVerified,
      "no chain verifier supplied, so no TCB status was reported to check"
    ));
  }

  const requiredFailure = checks.find((entry) => entry.required && !entry.passed);
  if (requiredFailure) {
    return failed(checks, policy, now, { binding, appCompose, measurements, tcbStatus });
  }

  return {
    status: "ok",
    verificationLevel: chainVerified ? "hardware-verified" : "provider-attested",
    checks,
    reason: null,
    binding,
    appCompose,
    measurements,
    tcbStatus,
    policySource: policy.source,
    policyVersion: policy.version,
    verifiedAtMs: now
  };
}
