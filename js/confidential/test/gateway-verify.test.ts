// Fail-closed acceptance tests for hop 1: AnonRouter's own confidential routing
// plane. Every test starts from a document that verifies, then breaks exactly one
// thing and asserts the specific required check that catches it. A verifier that
// silently tolerated any of these would let a non-attested data plane pass as
// attested, which is the whole failure this SDK exists to prevent.

import { describe, expect, it } from "vitest";
import {
  gatewayBindingHash,
  GATEWAY_BINDING_VERSION,
  type GatewayAttestationBinding
} from "../src/gateway/binding.js";
import { loadGatewayPolicy, type GatewayMeasurementPolicy } from "../src/gateway/policy.js";
import { replayRegister, rtmr3EventDigest } from "../src/gateway/eventLog.js";
import {
  verifyGatewayAttestation,
  type GatewayAttestationEvidence,
  type GatewayVerificationExpectations,
  type TdxChainVerifier
} from "../src/gateway/verify.js";
import {
  buildAppCompose,
  buildSyntheticEventLog,
  buildSyntheticTdxQuote,
  buildVmConfig,
  quoteRegister,
  QUOTE_OFFSETS,
  rtmr3Event,
  rtmr3EventV2,
  rtmr3EventWithDigest,
  SYNTHETIC_MR_CONFIG_ID,
  SYNTHETIC_OS_IMAGE_HASH
} from "./helpers/gateway-fixtures.js";

const NONCE = "9".repeat(64);
const ORIGIN = "https://tee.anonrouter.ai";
const APP_ID = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98";
const RELEASE_ID = "anonrouter-tee@c7b32e0";
const PUBLIC_KEY = "ab".repeat(32);
const TLS_SPKI = "11".repeat(32);
const NOW = 1_760_000_000_000;

const compose = buildAppCompose();

function policy(overrides: Partial<GatewayMeasurementPolicy> = {}): GatewayMeasurementPolicy {
  return {
    ...loadGatewayPolicy({
      source: "anonrouter-sdk@test",
      version: "2026.08.29",
      origins: [ORIGIN],
      appIds: [APP_ID],
      composeHashes: [compose.hash],
      releaseIds: [RELEASE_ID],
      requireInTeeTls: false,
      requirePrivateLogs: true,
      requireDigestPinnedImages: true,
      requireHardwareVerified: false,
      acceptableTcbStatuses: ["UpToDate"],
      requireEvidenceExpiry: false,
      maxEvidenceAgeMs: 300_000
    }),
    ...overrides
  };
}

function binding(overrides: Partial<GatewayAttestationBinding> = {}): GatewayAttestationBinding {
  return {
    v: GATEWAY_BINDING_VERSION,
    nonce: NONCE,
    app_id: APP_ID,
    instance_id: INSTANCE_ID,
    compose_hash: compose.hash,
    release_id: RELEASE_ID,
    origin: ORIGIN,
    key_alg: "x25519",
    public_key: PUBLIC_KEY,
    transport: "gateway-tls",
    tls_spki_sha256: null,
    ...overrides
  };
}

interface EvidenceOverrides {
  binding?: GatewayAttestationBinding;
  manifest?: string;
  quoteReportData?: string;
  debug?: boolean;
  teeType?: number;
  extraRtmr3?: ReturnType<typeof rtmr3Event>[];
  keyProviderId?: string;
  composeHashEventPayload?: string;
  tamperComposeEventPayload?: boolean;
  breakRtmr3?: boolean;
  mrConfigId?: string;
  measuredOsImageHash?: string;
  /** The vm_config the CVM serves. `null` omits it entirely. */
  vmConfig?: string | null;
  eventLog?: unknown;
}

function evidence(overrides: EvidenceOverrides = {}): GatewayAttestationEvidence {
  const value = overrides.binding ?? binding();
  const log = buildSyntheticEventLog({
    appId: APP_ID,
    composeHash: overrides.composeHashEventPayload ?? value.compose_hash,
    instanceId: value.instance_id,
    keyProviderId: overrides.keyProviderId,
    osImageHash: overrides.measuredOsImageHash,
    extraRtmr3: overrides.extraRtmr3
  });
  const events = log.events.map((event) => {
    if (!overrides.tamperComposeEventPayload || event.event !== "compose-hash") return event;
    // Keep the measured digest, rewrite only the readable payload. This is the
    // attack the digest-recomputation check exists to stop.
    return { ...event, event_payload: "c".repeat(64) };
  });
  return {
    binding: value,
    quote: buildSyntheticTdxQuote({
      reportDataHex: overrides.quoteReportData ?? gatewayBindingHash(value),
      rtmr0: log.rtmr0,
      rtmr1: log.rtmr1,
      rtmr2: log.rtmr2,
      rtmr3: overrides.breakRtmr3 ? "f".repeat(96) : log.rtmr3,
      mrConfigId: overrides.mrConfigId,
      debug: overrides.debug,
      teeType: overrides.teeType
    }),
    event_log: overrides.eventLog !== undefined ? overrides.eventLog : JSON.stringify(events),
    app_compose: overrides.manifest ?? compose.manifest,
    issued_at_ms: NOW - 500,
    ...(overrides.vmConfig === null
      ? {}
      : { vm_config: overrides.vmConfig ?? buildVmConfig(overrides.measuredOsImageHash) })
  };
}

/** A policy that additionally pins the platform stack. */
function platformPolicy(overrides: Record<string, unknown> = {}): GatewayMeasurementPolicy {
  const quote = evidence().quote;
  return policy({
    platform: {
      mrTd: [quoteRegister(quote, QUOTE_OFFSETS.mrTd)],
      mrConfigId: [SYNTHETIC_MR_CONFIG_ID],
      rtmr0: [quoteRegister(quote, QUOTE_OFFSETS.rtmr0)],
      rtmr1: [quoteRegister(quote, QUOTE_OFFSETS.rtmr1)],
      rtmr2: [quoteRegister(quote, QUOTE_OFFSETS.rtmr2)],
      osImageHash: [SYNTHETIC_OS_IMAGE_HASH],
      ...overrides
    } as GatewayMeasurementPolicy["platform"]
  });
}

function expectations(overrides: Partial<GatewayVerificationExpectations> = {}): GatewayVerificationExpectations {
  return { nonce: NONCE, origin: ORIGIN, policy: policy(), now: NOW, ...overrides };
}

function namedCheck(result: ReturnType<typeof verifyGatewayAttestation>, name: string) {
  const entry = result.checks.find((c) => c.name === name);
  expect(entry, `check ${name} missing`).toBeDefined();
  return entry!;
}

describe("gateway attestation verifier", () => {
  it("accepts a well-formed document and caps the verdict at provider-attested", () => {
    const result = verifyGatewayAttestation(evidence(), expectations());
    expect(result.reason).toBeNull();
    expect(result.status).toBe("ok");
    // No DCAP chain verifier was supplied, so hardware-verified must NOT appear.
    expect(result.verificationLevel).toBe("provider-attested");
    expect(result.appCompose?.publicLogs).toBe(false);
    expect(result.appCompose?.images.every((i) => i.digestPinned)).toBe(true);
    expect(result.measurements?.rtmr3).toMatch(/^[0-9a-f]{96}$/);
    expect(result.binding?.origin).toBe(ORIGIN);
  });

  it("reports hardware-verified only when a chain verifier actually passes", () => {
    const passing: TdxChainVerifier = {
      implementation: "test-dcap",
      verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" })
    };
    const ok = verifyGatewayAttestation(evidence(), expectations({ chainVerifier: passing }));
    expect(ok.verificationLevel).toBe("hardware-verified");
    expect(ok.tcbStatus).toBe("UpToDate");

    const rejecting: TdxChainVerifier = {
      implementation: "test-dcap",
      verifyChain: () => ({ verified: false, tcbStatus: "OutOfDate" })
    };
    const bad = verifyGatewayAttestation(evidence(), expectations({ chainVerifier: rejecting }));
    expect(bad.status).toBe("failed");
    expect(bad.reason).toBe("quote_signature_chain");
  });

  it("fails closed when the policy demands hardware verification and no engine is wired", () => {
    // This package ships no DCAP engine, so a requireHardwareVerified policy must
    // fail loudly rather than quietly accepting at provider-attested.
    const result = verifyGatewayAttestation(
      evidence(),
      expectations({ policy: policy({ requireHardwareVerified: true }) })
    );
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("quote_signature_chain");
    expect(namedCheck(result, "quote_signature_chain").detail).toContain("no DCAP chain verifier");
  });

  describe("binding integrity", () => {
    it("rejects a binding whose digest is not the quote's report_data", () => {
      const result = verifyGatewayAttestation(
        evidence({ quoteReportData: "0".repeat(128) }),
        expectations()
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("report_data_binds_binding");
    });

    it("rejects a malformed binding before hashing anything", () => {
      const result = verifyGatewayAttestation(
        { ...evidence(), binding: { ...binding(), surprise: true } },
        expectations()
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("binding_wellformed");
    });

    it("rejects a quote bound to somebody else's nonce", () => {
      const other = binding({ nonce: "1".repeat(64) });
      const result = verifyGatewayAttestation(evidence({ binding: other }), expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("nonce_matches_request");
    });

    it("rejects a quote bound to a different origin than the one we connected to", () => {
      const elsewhere = binding({ origin: "https://evil.example" });
      const result = verifyGatewayAttestation(
        evidence({ binding: elsewhere }),
        expectations({ policy: policy({ origins: [ORIGIN, "https://evil.example"] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("origin_matches_connection");
    });
  });

  describe("quote structure", () => {
    it("rejects an unparseable quote", () => {
      const result = verifyGatewayAttestation({ ...evidence(), quote: "not-a-quote" }, expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("quote_parsed");
    });

    it("rejects a non-TDX tee type", () => {
      const result = verifyGatewayAttestation(evidence({ teeType: 0 }), expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("quote_is_tdx");
    });

    it("rejects a debug TD, where nothing measured is confidential", () => {
      const result = verifyGatewayAttestation(evidence({ debug: true }), expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("quote_not_debug");
    });
  });

  describe("event log", () => {
    it("rejects a log that does not replay to the quote's registers", () => {
      const result = verifyGatewayAttestation(evidence({ breakRtmr3: true }), expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("event_log_replays_rtmrs");
    });

    it("rejects a rewritten compose-hash payload even when the digests still replay", () => {
      // The genuine quote and genuine digests are untouched; only the readable
      // payload beside them was rewritten. Digest recomputation is what catches it.
      const result = verifyGatewayAttestation(evidence({ tamperComposeEventPayload: true }), expectations());
      expect(result.status).toBe("failed");
      expect(["event_digests_commit_to_payloads", "event_log_replays_rtmrs"]).toContain(result.reason);
    });

    it("rejects a compose hash the hardware never measured", () => {
      const result = verifyGatewayAttestation(
        evidence({ composeHashEventPayload: "a".repeat(64) }),
        expectations()
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("compose_hash_measured_in_rtmr3");
    });

    it("rejects an unparseable log instead of treating it as absent", () => {
      const result = verifyGatewayAttestation(evidence({ eventLog: "{not json" }), expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("event_log_replays_rtmrs");
    });

    it("rejects a duplicated compose-hash event", () => {
      const result = verifyGatewayAttestation(
        evidence({ extraRtmr3: [rtmr3Event("compose-hash", "b".repeat(64))] }),
        expectations()
      );
      expect(result.status).toBe("failed");
    });

    it("accepts a V2 event that publishes its own preimage", () => {
      const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: compose.hash, instanceId: INSTANCE_ID });
      // A V2 entry's digest is SHA-384 of its published preimage, not the V1
      // concatenation, so RTMR3 has to be replayed over the V2 digests.
      const v2Events = log.events.map((event) => (event.imr === 3 && event.event.length > 0
        ? rtmr3EventV2(event.event, event.event_payload, event.event_type)
        : event));
      const rtmr3 = replayRegister(v2Events
        .filter((event) => event.imr === 3)
        .map((event) => rtmr3EventDigest(event) ?? "ff".repeat(48)));
      const value = binding();
      const result = verifyGatewayAttestation(
        {
          binding: value,
          quote: buildSyntheticTdxQuote({
            reportDataHex: gatewayBindingHash(value),
            rtmr0: log.rtmr0,
            rtmr1: log.rtmr1,
            rtmr2: log.rtmr2,
            rtmr3
          }),
          event_log: JSON.stringify(v2Events),
          app_compose: compose.manifest,
          issued_at_ms: NOW - 500,
          vm_config: buildVmConfig()
        },
        expectations()
      );
      expect(result.reason).toBeNull();
      expect(result.status).toBe("ok");
    });

    it("rejects a V2 event whose preimage names a different payload than it displays", () => {
      const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: compose.hash, instanceId: INSTANCE_ID });
      const v2Events = log.events.map((event) => {
        if (event.imr !== 3 || event.event.length === 0) return event;
        const v2 = rtmr3EventV2(event.event, event.event_payload, event.event_type);
        // Genuine preimage and digest, rewritten display payload.
        return event.event === "compose-hash" ? { ...v2, event_payload: "c".repeat(64) } : v2;
      });
      const rtmr3 = replayRegister(v2Events
        .filter((event) => event.imr === 3)
        .map((event) => rtmr3EventDigest(event) ?? "ff".repeat(48)));
      const value = binding();
      const result = verifyGatewayAttestation(
        {
          binding: value,
          quote: buildSyntheticTdxQuote({
            reportDataHex: gatewayBindingHash(value),
            rtmr0: log.rtmr0,
            rtmr1: log.rtmr1,
            rtmr2: log.rtmr2,
            rtmr3
          }),
          event_log: JSON.stringify(v2Events),
          app_compose: compose.manifest,
          issued_at_ms: NOW - 500,
          vm_config: buildVmConfig()
        },
        expectations()
      );
      expect(result.status).toBe("failed");
      expect(["event_digests_commit_to_payloads", "event_log_replays_rtmrs"]).toContain(result.reason);
    });

    it("accepts a V1 event that carries the digest it derives to", () => {
      const derived = rtmr3EventWithDigest("app-id", APP_ID);
      expect(derived.digest).toMatch(/^[0-9a-f]{96}$/);
      // Self-consistency is what makes a supplied digest safe to display.
      expect(derived.digest).toBe(rtmr3EventWithDigest("app-id", APP_ID).digest);
    });
  });

  describe("app-compose manifest", () => {
    it("rejects a manifest that is not the measured one", () => {
      const other = buildAppCompose({ name: "something-else" });
      const result = verifyGatewayAttestation(evidence({ manifest: other.manifest }), expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("app_compose_matches_measurement");
    });

    it("rejects public logs when the policy requires them off", () => {
      const loud = buildAppCompose({ public_logs: true });
      const result = verifyGatewayAttestation(
        evidence({ binding: binding({ compose_hash: loud.hash }), manifest: loud.manifest }),
        expectations({ policy: policy({ composeHashes: [loud.hash] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("compose_public_logs_disabled");
    });

    it("rejects an image reference that is not digest-pinned", () => {
      const floating = buildAppCompose({
        docker_compose_file: "services:\n  relay:\n    image: ghcr.io/example/anonrouter:latest"
      });
      const result = verifyGatewayAttestation(
        evidence({ binding: binding({ compose_hash: floating.hash }), manifest: floating.manifest }),
        expectations({ policy: policy({ composeHashes: [floating.hash] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("compose_images_digest_pinned");
    });
  });

  describe("locally pinned identity", () => {
    it("rejects an app id that is not on the allowlist", () => {
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: policy({ appIds: ["dead".repeat(10)] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("app_id_pinned");
    });

    it("rejects a binding whose app id the event log never measured", () => {
      // Distinct from app_id_pinned: here the CLAIMED app id is on the allowlist
      // but the hardware measured a different one, so the TD is claiming an
      // identity it was not provisioned with.
      const claimed = binding({ app_id: "aaaa".repeat(10) });
      const result = verifyGatewayAttestation(
        {
          ...evidence({ binding: claimed }),
          // Keep the log measuring the ORIGINAL app id.
          event_log: evidence().event_log
        },
        expectations({ policy: policy({ appIds: [APP_ID, "aaaa".repeat(10)] }) })
      );
      expect(result.status).toBe("failed");
      expect(["app_id_measured", "event_log_replays_rtmrs"]).toContain(result.reason);
    });

    it("rejects a compose hash that is not on the allowlist", () => {
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: policy({ composeHashes: ["ab".repeat(32)] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("compose_hash_pinned");
    });

    it("rejects a release the client did not review", () => {
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: policy({ releaseIds: ["anonrouter-tee@somethingelse"] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("release_pinned");
    });

    it("rejects an origin the policy does not authorize", () => {
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: policy({ origins: ["https://other.anonrouter.ai"] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("origin_pinned");
    });

    it("pins the key provider, so a CVM under a different KMS fails", () => {
      const pinned = policy({ keyProviderId: "aa".repeat(32) });
      const wrongKms = verifyGatewayAttestation(evidence(), expectations({ policy: pinned }));
      expect(wrongKms.status).toBe("failed");
      expect(wrongKms.reason).toBe("key_provider_pinned");

      const rightKms = verifyGatewayAttestation(
        evidence({ keyProviderId: "aa".repeat(32) }),
        expectations({ policy: pinned })
      );
      expect(rightKms.status).toBe("ok");
    });

    it("records an unpinned key provider as a visible gap rather than a pass", () => {
      const result = verifyGatewayAttestation(evidence(), expectations());
      const entry = namedCheck(result, "key_provider_pinned");
      expect(entry.passed).toBe(false);
      expect(entry.required).toBe(false);
      expect(entry.detail).toContain("policy pins no key provider");
    });

    it("pins the platform stack when the policy names one", () => {
      expect(verifyGatewayAttestation(evidence(), expectations({ policy: platformPolicy() })).status).toBe("ok");

      const wrongFirmware = platformPolicy({ rtmr0: ["cc".repeat(48)] });
      const result = verifyGatewayAttestation(evidence(), expectations({ policy: wrongFirmware }));
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("platform_measurements_pinned");
    });

    it("pins the OS image separately from the opaque registers", () => {
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: platformPolicy({ osImageHash: ["ee".repeat(32)] }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("os_image_pinned");
    });
  });

  describe("vm_config anchoring", () => {
    it("rejects a vm_config naming an OS image the hardware did not measure", () => {
      const result = verifyGatewayAttestation(
        evidence({ vmConfig: buildVmConfig("cc".repeat(32)) }),
        expectations()
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("vm_config_matches_measured_os_image");
    });

    it("records a missing vm_config as an advisory gap, not a pass", () => {
      const result = verifyGatewayAttestation(evidence({ vmConfig: null }), expectations());
      expect(result.status).toBe("ok");
      const entry = namedCheck(result, "vm_config_matches_measured_os_image");
      expect(entry.passed).toBe(false);
      expect(entry.required).toBe(false);
      expect(entry.detail).toContain("unanchored");
    });
  });

  describe("transport binding", () => {
    it("fails closed on gateway-tls when the policy requires in-TEE TLS", () => {
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: policy({ requireInTeeTls: true }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("transport_terminates_in_tee");
    });

    it("binds the observed certificate to the quote when in-TEE TLS is required", () => {
      const inTee = binding({ transport: "in-tee-tls", tls_spki_sha256: TLS_SPKI });
      const strict = policy({ requireInTeeTls: true });

      const matched = verifyGatewayAttestation(
        evidence({ binding: inTee }),
        expectations({ policy: strict, observedTlsSpkiSha256: TLS_SPKI })
      );
      expect(matched.reason).toBeNull();
      expect(matched.status).toBe("ok");

      const mismatched = verifyGatewayAttestation(
        evidence({ binding: inTee }),
        expectations({ policy: strict, observedTlsSpkiSha256: "22".repeat(32) })
      );
      expect(mismatched.status).toBe("failed");
      expect(mismatched.reason).toBe("tls_certificate_bound_to_quote");
    });

    it("records an unobservable certificate as a gap a browser cannot close", () => {
      const inTee = binding({ transport: "in-tee-tls", tls_spki_sha256: TLS_SPKI });
      const result = verifyGatewayAttestation(
        evidence({ binding: inTee }),
        expectations({ policy: policy({ requireInTeeTls: true }) })
      );
      // Still ok, because the check is advisory when the caller cannot observe,
      // but the gap is named rather than assumed away.
      expect(result.status).toBe("ok");
      const entry = namedCheck(result, "tls_certificate_bound_to_quote");
      expect(entry.passed).toBe(false);
      expect(entry.required).toBe(false);
      expect(entry.detail).toContain("did not observe");
    });

    it("names gateway-tls as an advisory weakness when the policy tolerates it", () => {
      const result = verifyGatewayAttestation(evidence(), expectations());
      const entry = namedCheck(result, "transport_terminates_in_tee");
      expect(entry.passed).toBe(false);
      expect(entry.required).toBe(false);
      expect(entry.detail).toContain("platform gateway");
    });
  });

  it("never throws on hostile input, so a caller reading only status is safe", () => {
    const hostile: unknown[] = [
      null,
      {},
      { binding: null, quote: null, event_log: null, app_compose: null },
      { binding: [], quote: 1, event_log: {}, app_compose: 2 },
      { binding: binding(), quote: "zz", event_log: "[]", app_compose: "" }
    ];
    for (const input of hostile) {
      const result = verifyGatewayAttestation(input as GatewayAttestationEvidence, expectations());
      expect(result.status).toBe("failed");
      expect(result.reason).toBeTruthy();
    }
  });
});
