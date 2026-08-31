// Generate shared/vectors/gateway-verdicts.json.
//
// `attestation.json` pins the complete verdict for every hop 2 case. Hop 1 had no
// equivalent, so the two languages agreed about the binding digest and the quote
// parse but nothing pinned the VERDICT: which checks are required, what a failure
// is called, and which single check a given tamper is supposed to fail. A change
// that landed in one language and not the other could pass both suites.
//
// This fixes that with one base evidence document and a list of cases that each
// change the smallest possible thing. Both suites load the SAME bytes, run their
// own verifier, and must produce the same status, level, reason, failed required
// checks and unmet advisory checks.
//
//   npx tsx scripts/gen-gateway-verdict-vectors.ts
//
// Every case is run through the real verifier and whatever it returns is recorded,
// so the file always describes actual behavior. Read the resulting diff carefully:
// a changed expectation is a changed security decision, not a test fixup. If a
// case flips from `failed` to `ok`, or a check leaves `failedRequiredChecks`, say
// why in the pull request.

import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gatewayBindingHash, GATEWAY_BINDING_VERSION } from "../src/gateway/binding.js";
import { loadGatewayPolicy } from "../src/gateway/policy.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence, type TdxChainVerifier } from "../src/gateway/verify.js";
import { replayRegister } from "../src/gateway/eventLog.js";
import {
  buildAppCompose,
  buildSyntheticEventLog,
  buildSyntheticTdxQuote,
  buildVmConfig,
  rtmr3EventV2,
  rtmr3EventWithDigest,
  SYNTHETIC_MR_CONFIG_ID,
  SYNTHETIC_OS_IMAGE_HASH
} from "../test/helpers/gateway-fixtures.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, "..", "..", "..", "shared", "vectors", "gateway-verdicts.json");

const NONCE = "9".repeat(64);
const ORIGIN = "https://tee.anonrouter.ai";
const APP_ID = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98";
const RELEASE_ID = "anonrouter-tee@c7b32e0";
const KEY_PROVIDER = "aa".repeat(33);
const SPKI = "cc".repeat(32);
const NOW = 1_760_000_000_000;

const compose = buildAppCompose();
const log = buildSyntheticEventLog({
  appId: APP_ID,
  composeHash: compose.hash,
  instanceId: INSTANCE_ID,
  keyProviderId: KEY_PROVIDER
});

const baseBinding = {
  v: GATEWAY_BINDING_VERSION,
  nonce: NONCE,
  app_id: APP_ID,
  instance_id: INSTANCE_ID,
  compose_hash: compose.hash,
  release_id: RELEASE_ID,
  origin: ORIGIN,
  key_alg: "x25519" as const,
  public_key: "ab".repeat(32),
  transport: "in-tee-tls" as const,
  tls_spki_sha256: SPKI
};

/** Build a quote whose report_data commits to `binding` and whose registers match `log`. */
function quoteFor(binding: unknown, overrides: Record<string, unknown> = {}): string {
  return buildSyntheticTdxQuote({
    reportDataHex: gatewayBindingHash(binding as never),
    mrTd: "3f".repeat(48),
    mrConfigId: SYNTHETIC_MR_CONFIG_ID,
    rtmr0: log.rtmr0,
    rtmr1: log.rtmr1,
    rtmr2: log.rtmr2,
    rtmr3: log.rtmr3,
    ...overrides
  });
}

const baseEvidence = {
  binding: baseBinding,
  quote: quoteFor(baseBinding),
  event_log: JSON.stringify(log.events),
  app_compose: compose.manifest,
  vm_config: buildVmConfig(),
  issued_at_ms: NOW - 1_000
};

const basePolicy = {
  source: "anonrouter-sdk@gateway-verdict-vectors",
  version: "1",
  origins: [ORIGIN],
  appIds: [APP_ID],
  composeHashes: [compose.hash],
  releaseIds: [RELEASE_ID],
  keyProviderId: KEY_PROVIDER,
  platform: {
    mrTd: ["3f".repeat(48)],
    mrConfigId: [SYNTHETIC_MR_CONFIG_ID],
    rtmr0: [log.rtmr0],
    rtmr1: [log.rtmr1],
    rtmr2: [log.rtmr2],
    osImageHash: [SYNTHETIC_OS_IMAGE_HASH]
  },
  requireInTeeTls: false,
  requirePrivateLogs: true,
  requireDigestPinnedImages: true,
  requireHardwareVerified: false,
  acceptableTcbStatuses: ["UpToDate"],
  requireEvidenceExpiry: true,
  maxEvidenceAgeMs: 300_000
};

const baseExpectations = { nonce: NONCE, origin: ORIGIN, nowMs: NOW };

/** A complete, self-consistent document for a variant compose manifest. */
function documentForCompose(overrides: Record<string, unknown>) {
  const altered = buildAppCompose(overrides);
  const alteredLog = buildSyntheticEventLog({
    appId: APP_ID, composeHash: altered.hash, instanceId: INSTANCE_ID, keyProviderId: KEY_PROVIDER
  });
  const binding = { ...baseBinding, compose_hash: altered.hash };
  return {
    hash: altered.hash,
    evidence: {
      binding,
      quote: buildSyntheticTdxQuote({
        reportDataHex: gatewayBindingHash(binding as never),
        mrTd: "3f".repeat(48),
        mrConfigId: SYNTHETIC_MR_CONFIG_ID,
        rtmr0: alteredLog.rtmr0,
        rtmr1: alteredLog.rtmr1,
        rtmr2: alteredLog.rtmr2,
        rtmr3: alteredLog.rtmr3
      }),
      event_log: JSON.stringify(alteredLog.events),
      app_compose: altered.manifest,
      vm_config: buildVmConfig(),
      issued_at_ms: NOW - 1_000
    }
  };
}

/** The same CVM emitting the dstack V2 event form, with a quote to match. */
const v2Log = (() => {
  const v1 = buildSyntheticEventLog({
    appId: APP_ID, composeHash: compose.hash, instanceId: INSTANCE_ID, keyProviderId: KEY_PROVIDER
  });
  const events = v1.events.map((e) => (e.imr === 3 ? rtmr3EventV2(e.event, e.event_payload, e.event_type) : e));
  const rtmr3 = replayRegister(events.filter((e) => e.imr === 3).map((e) => e.digest));
  return { events, rtmr0: v1.rtmr0, rtmr1: v1.rtmr1, rtmr2: v1.rtmr2, rtmr3 };
})();

/** The same CVM whose log names compose-hash twice. */
const duplicateLog = buildSyntheticEventLog({
  appId: APP_ID, composeHash: compose.hash, instanceId: INSTANCE_ID, keyProviderId: KEY_PROVIDER,
  extraRtmr3: [rtmr3EventWithDigest("compose-hash", compose.hash)]
});

const publicLogsDocument = documentForCompose({ public_logs: true });
const taggedImageDocument = documentForCompose({
  docker_compose_file: "services:\n  relay:\n    image: ghcr.io/example/anonrouter:latest"
});

/** Flip one bit in the byte at `offset` of a hex-encoded quote. */
function flipQuoteByte(quoteHex: string, offset: number): string {
  const at = offset * 2;
  const byte = parseInt(quoteHex.slice(at, at + 2), 16) ^ 0x01;
  return quoteHex.slice(0, at) + byte.toString(16).padStart(2, "0") + quoteHex.slice(at + 2);
}

/** The event log with one entry rewritten. */
function logWith(mutate: (events: Record<string, unknown>[]) => void): string {
  const events = JSON.parse(JSON.stringify(log.events)) as Record<string, unknown>[];
  mutate(events);
  return JSON.stringify(events);
}

interface CaseInput {
  name: string;
  why: string;
  evidence?: Record<string, unknown>;
  binding?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  expectations?: Record<string, unknown>;
  /** A stub chain verifier both languages construct locally, or null for none. */
  chainVerifier?: { verified: boolean; tcbStatus: string | null } | null;
  observedTlsSpki?: { supplied: boolean; value: string | null };
}

const inputs: CaseInput[] = [
  {
    name: "everything holds",
    why: "The baseline. Every other case changes exactly one thing from here, so a failure below is caused by that change and nothing else."
  },
  {
    name: "the V2 event-log form, which real CVMs emit",
    why: "dstack V2 publishes the hashed bytes as `preimage`. The verifier must accept it without falling back to the V1 concatenation, and must still require the preimage to name the same event and payload that are displayed.",
    evidence: {
      event_log: JSON.stringify(v2Log.events),
      quote: quoteFor(baseBinding, {
        rtmr0: v2Log.rtmr0, rtmr1: v2Log.rtmr1, rtmr2: v2Log.rtmr2, rtmr3: v2Log.rtmr3
      })
    }
  },
  {
    name: "REPLAY: a nonce the document was never bound to",
    why: "The primary anti-replay control. A document that verified a moment ago must not verify for a challenge it never saw.",
    expectations: { nonce: "1".repeat(64) }
  },
  {
    name: "WRONG ORIGIN: the document names another deployment",
    why: "The document belongs to whoever it names. Accepting it elsewhere would let one verified deployment vouch for an unverified one.",
    expectations: { origin: "https://someone-else.example" }
  },
  {
    name: "TAMPERED BINDING: a rewritten release id",
    why: "report_data is SHA-512 of the whole binding, so changing any field breaks it. This is what stops an operator renaming a build after the fact.",
    binding: { release_id: "anonrouter-tee@attacker" }
  },
  {
    name: "TAMPERED BINDING: a rewritten TLS fingerprint",
    why: "The certificate the TD attests is inside the hashed binding, which is what closes the earlier fingerprint-hearsay bug where an operator could name a key the TD never held.",
    binding: { tls_spki_sha256: "ab".repeat(32) }
  },
  {
    name: "MALFORMED BINDING: an unknown field",
    why: "A verifier that ignored an unknown field would accept a digest computed over data it never inspected.",
    binding: { surprise: "extra" }
  },
  {
    name: "TAMPERED QUOTE: one flipped byte in report_data",
    why: "The single-bit case. Nothing else about the document changes.",
    evidence: { quote: flipQuoteByte(baseEvidence.quote, 568) }
  },
  {
    name: "TAMPERED QUOTE: a flipped RTMR0 byte",
    why: "The event log no longer replays to the register it claims to describe.",
    evidence: { quote: flipQuoteByte(baseEvidence.quote, 376) }
  },
  {
    name: "DEBUG TD",
    why: "A debug TD lets the host read and modify guest memory, so nothing measured inside it is confidential. Unconditionally fatal.",
    evidence: { quote: quoteFor(baseBinding, { debug: true }) }
  },
  {
    name: "NOT A TDX QUOTE",
    why: "A quote for another TEE type is not evidence about a TD.",
    evidence: { quote: quoteFor(baseBinding, { teeType: 0x00000000 }) }
  },
  {
    name: "TAMPERED EVENT LOG: a rewritten digest",
    why: "The replay stops reproducing the hardware registers.",
    evidence: { event_log: logWith((events) => { events[0].digest = "00".repeat(48); }) }
  },
  {
    name: "REWRITTEN PAYLOAD: the compose hash renamed beside an empty digest",
    why: "The natural attack: keep a genuine quote and log, rewrite only the readable payload to something the policy accepts. It fails because RTMR3 digests are DERIVED from each event's own fields rather than read out of the log.",
    evidence: { event_log: logWith((events) => {
      const target = events.find((e) => e.event === "compose-hash")!;
      target.event_payload = "ff".repeat(32);
    }) }
  },
  {
    name: "SUPPLIED DIGEST that does not commit to its payload",
    why: "If a log supplies a digest instead of leaving it empty, it must still agree with the payload printed beside it, or a server could ship a digest that replays while displaying something else.",
    evidence: { event_log: logWith((events) => {
      const target = events.find((e) => e.event === "compose-hash")!;
      target.digest = "ab".repeat(48);
    }) }
  },
  {
    name: "DUPLICATE compose-hash events",
    why: "Two entries with the same name would let a server present whichever value the reader happens to pick first. It must make EVERY identity read out of that log unusable, not just the duplicated one.",
    evidence: {
      event_log: JSON.stringify(duplicateLog.events),
      quote: quoteFor(baseBinding, {
        rtmr0: duplicateLog.rtmr0, rtmr1: duplicateLog.rtmr1,
        rtmr2: duplicateLog.rtmr2, rtmr3: duplicateLog.rtmr3
      })
    }
  },
  {
    name: "TAMPERED MANIFEST: one appended space",
    why: "The manifest is measured by SHA-256, so any edit makes it a different document. Without this check the manifest is decorative.",
    evidence: { app_compose: `${compose.manifest} ` }
  },
  {
    name: "PUBLIC LOGS: the attested configuration publishes container logs",
    why: "Turns 'we do not publish logs' from a promise into a measured configuration fact. The policy pins this document's own compose hash, so compose_public_logs_disabled is the ONLY thing that fails.",
    evidence: publicLogsDocument.evidence,
    policy: { composeHashes: [publicLogsDocument.hash] }
  },
  {
    name: "UNPINNED IMAGE: a container referenced by tag",
    why: "A tag can be repointed later, so the compose hash would pin something mutable. The policy pins this document's own compose hash, so compose_images_digest_pinned is the ONLY thing that fails.",
    evidence: taggedImageDocument.evidence,
    policy: { composeHashes: [taggedImageDocument.hash] }
  },
  {
    name: "APP ID not on the allowlist",
    why: "A policy-pin failure, which is the ordinary outcome after a release. Distinguishable from a cryptographic failure by name.",
    policy: { appIds: ["ff".repeat(20)] }
  },
  {
    name: "COMPOSE HASH not on the allowlist",
    why: "The deployment moved to a configuration nobody reviewed.",
    policy: { composeHashes: ["ff".repeat(32)] }
  },
  {
    name: "RELEASE not on the allowlist",
    why: "The release id is an operator-set string, so this catches a build nobody named.",
    policy: { releaseIds: ["anonrouter-tee@unreviewed"] }
  },
  {
    name: "ORIGIN not authorized by the policy",
    why: "A policy authorizes named origins; an unlisted one fails closed rather than being accepted because everything else matched.",
    policy: { origins: ["https://other.anonrouter.ai"] },
    expectations: { origin: "https://other.anonrouter.ai" }
  },
  {
    name: "PLATFORM measurements not pinned",
    why: "The firmware or guest OS changed underneath an otherwise matching identity.",
    policy: { platform: {
      mrTd: ["ab".repeat(48)], mrConfigId: ["ab".repeat(48)],
      rtmr0: ["ab".repeat(48)], rtmr1: ["ab".repeat(48)], rtmr2: ["ab".repeat(48)],
      osImageHash: ["ab".repeat(32)]
    } }
  },
  {
    name: "KEY PROVIDER not pinned",
    why: "A CVM whose keys come from a different KMS is a different trust domain even at the same compose hash.",
    policy: { keyProviderId: "bb".repeat(33) }
  },
  {
    name: "NO KEY PROVIDER pinned at all",
    why: "Absent rather than wrong. The check becomes ADVISORY and the verdict still passes, but the gap is recorded rather than assumed away.",
    policy: { keyProviderId: undefined }
  },
  {
    name: "VM CONFIG names an OS image the hardware did not measure",
    why: "vm_config is what an auditor re-feeds to dstack-mr. A CVM naming a different image would send them to reproduce the wrong measurements and conclude the quote was forged.",
    evidence: { vm_config: buildVmConfig("ab".repeat(32)) }
  },
  {
    name: "NO VM CONFIG at all",
    why: "Absent rather than wrong, so the check is advisory: offline measurement recomputation is unanchored, and that is recorded.",
    evidence: { vm_config: undefined }
  },
  {
    name: "STALE EVIDENCE",
    why: "Defence in depth behind the nonce. The document is outside the age window the policy allows.",
    expectations: { nowMs: NOW + 3_600_000 }
  },
  {
    name: "NO TIMESTAMP, with expiry required",
    why: "A document that cannot be aged has not been shown to be fresh. Treating unmeasurable as acceptable is how an expiry check quietly stops existing.",
    evidence: { issued_at_ms: undefined }
  },
  {
    name: "NO TIMESTAMP, with expiry not required",
    why: "The same document under a policy that does not require expiry: the check becomes advisory and the verdict passes.",
    evidence: { issued_at_ms: undefined },
    policy: { requireEvidenceExpiry: false }
  },
  {
    name: "IN-TEE TLS required, but the platform gateway terminates it",
    why: "When TLS terminates in front of the TD, the transport is not proof of who you are talking to.",
    binding: { transport: "gateway-tls", tls_spki_sha256: null },
    policy: { requireInTeeTls: true }
  },
  {
    name: "IN-TEE TLS required and the observed certificate matches",
    why: "The strongest transport statement available: the TD attested the very key the caller's session used.",
    policy: { requireInTeeTls: true },
    observedTlsSpki: { supplied: true, value: SPKI }
  },
  {
    name: "IN-TEE TLS required and the observed certificate does NOT match",
    why: "Someone is terminating the connection who is not the TD that attested.",
    policy: { requireInTeeTls: true },
    observedTlsSpki: { supplied: true, value: "dd".repeat(32) }
  },
  {
    name: "IN-TEE TLS required and the caller could not observe its certificate",
    why: "A browser cannot see its own certificate. The gap is recorded as advisory rather than assumed away, and the verdict still passes.",
    policy: { requireInTeeTls: true },
    observedTlsSpki: { supplied: false, value: null }
  },
  {
    name: "HARDWARE VERIFICATION required with no chain verifier",
    why: "A client whose engine is missing or unbuilt must fail loudly rather than quietly accept at the weaker level and report success.",
    policy: { requireHardwareVerified: true }
  },
  {
    name: "HARDWARE VERIFICATION with a passing chain verifier",
    why: "The only path to hardware_verified, and it requires an engine that actually ran.",
    policy: { requireHardwareVerified: true },
    chainVerifier: { verified: true, tcbStatus: "UpToDate" }
  },
  {
    name: "CHAIN VERIFIED but the TCB is not accepted",
    why: "THE case worth understanding: the signature is genuine and the machine holding your data has known unpatched vulnerabilities. quote_signature_chain passes while tcb_status_acceptable fails.",
    policy: { requireHardwareVerified: true },
    chainVerifier: { verified: true, tcbStatus: "OutOfDate" }
  },
  {
    name: "CHAIN VERIFIER reports no TCB status at all",
    why: "A status that cannot be read cannot be checked against the policy, so it is a failure rather than a pass with an unknown.",
    policy: { requireHardwareVerified: true },
    chainVerifier: { verified: true, tcbStatus: null }
  },
  {
    name: "CHAIN VERIFIER refuses the quote",
    why: "The engine said no. Nothing else in the document can compensate.",
    policy: { requireHardwareVerified: true },
    chainVerifier: { verified: false, tcbStatus: "UpToDate" }
  },
  {
    name: "a passing chain verifier under a policy that does not require it",
    why: "The verdict still reaches hardware_verified: the work was done, so reporting less would be as dishonest as reporting more.",
    chainVerifier: { verified: true, tcbStatus: "UpToDate" }
  }
];

/** Materialize one case's evidence, policy and expectations. */
function materialize(input: CaseInput) {
  const evidence: Record<string, unknown> = { ...baseEvidence };
  for (const [key, value] of Object.entries(input.evidence ?? {})) {
    // `undefined` means REMOVE the field, which is a distinct case from setting it
    // to null: an absent issued_at_ms is what an evidence document with no
    // timestamp at all looks like.
    if (value === undefined) delete evidence[key];
    else evidence[key] = value;
  }

  if (input.binding) {
    const binding = { ...(evidence.binding as Record<string, unknown>), ...input.binding };
    evidence.binding = binding;
    // The quote is deliberately left committing to the ORIGINAL binding, because
    // that is what a rewritten binding actually looks like. The transport cases
    // are the exception: they are about the policy reading a field, not about
    // breaking the digest, so those get a matching quote.
    if ("transport" in input.binding) evidence.quote = quoteFor(binding);
  }

  const policy: Record<string, unknown> = { ...basePolicy };
  for (const [key, value] of Object.entries(input.policy ?? {})) {
    if (value === undefined) delete policy[key];
    else policy[key] = value;
  }

  return {
    evidence,
    policy,
    expectations: { ...baseExpectations, ...(input.expectations ?? {}) },
    observedTlsSpki: input.observedTlsSpki ?? { supplied: false, value: null },
    chainVerifier: input.chainVerifier ?? null
  };
}

/**
 * Emit only what DIFFERS from the base, so a reviewer diffing this file after a
 * change sees the change rather than forty copies of the same quote.
 *
 * The merge both languages implement is deliberately trivial: shallow override,
 * plus an explicit list of removed keys, because JSON cannot express "absent" and
 * an absent `issued_at_ms` is a case that has to be reachable. The generator
 * asserts below that merging reproduces the exact document it verified, so the
 * merge rule is pinned by construction rather than by hope.
 */
function diffFromBase(base: Record<string, unknown>, full: Record<string, unknown>) {
  const overrides: Record<string, unknown> = {};
  const removed: string[] = [];
  for (const key of Object.keys(base)) {
    if (!(key in full)) removed.push(key);
  }
  for (const [key, value] of Object.entries(full)) {
    if (JSON.stringify(base[key]) !== JSON.stringify(value)) overrides[key] = value;
  }
  return { overrides, removed };
}

function mergeOnBase(
  base: Record<string, unknown>,
  overrides: Record<string, unknown>,
  removed: readonly string[]
): Record<string, unknown> {
  const merged = { ...base, ...overrides };
  for (const key of removed) delete merged[key];
  return merged;
}

const cases = inputs.map((input) => {
  const { evidence, policy, expectations, observedTlsSpki, chainVerifier } = materialize(input);

  const stub: TdxChainVerifier | undefined = chainVerifier
    ? {
      implementation: "vector-stub",
      verifyChain: () => ({
        verified: chainVerifier.verified,
        ...(chainVerifier.tcbStatus ? { tcbStatus: chainVerifier.tcbStatus } : {})
      })
    }
    : undefined;

  const result = verifyGatewayAttestation(evidence as unknown as GatewayAttestationEvidence, {
    nonce: expectations.nonce as string,
    origin: expectations.origin as string,
    policy: loadGatewayPolicy(policy),
    now: expectations.nowMs as number,
    ...(observedTlsSpki.supplied ? { observedTlsSpkiSha256: observedTlsSpki.value } : {}),
    ...(stub ? { chainVerifier: stub } : {})
  });

  const evidenceDiff = diffFromBase(baseEvidence as unknown as Record<string, unknown>, evidence);
  const policyDiff = diffFromBase(basePolicy as unknown as Record<string, unknown>, policy);
  const expectationDiff = diffFromBase(baseExpectations as unknown as Record<string, unknown>, expectations);

  // The round trip is the guarantee. If merging the emitted diff did not reproduce
  // the bytes that were verified, the vector would describe a document nobody ran.
  const evidenceRoundTrip = mergeOnBase(
    baseEvidence as unknown as Record<string, unknown>, evidenceDiff.overrides, evidenceDiff.removed);
  if (JSON.stringify(evidenceRoundTrip) !== JSON.stringify(evidence)) {
    throw new Error(`evidence diff does not round-trip for case: ${input.name}`);
  }
  const policyRoundTrip = mergeOnBase(
    basePolicy as unknown as Record<string, unknown>, policyDiff.overrides, policyDiff.removed);
  if (JSON.stringify(policyRoundTrip) !== JSON.stringify(policy)) {
    throw new Error(`policy diff does not round-trip for case: ${input.name}`);
  }

  return {
    name: input.name,
    why: input.why,
    evidence: evidenceDiff.overrides,
    evidenceRemoved: evidenceDiff.removed,
    policy: policyDiff.overrides,
    policyRemoved: policyDiff.removed,
    expectations: expectationDiff.overrides,
    observedTlsSpki,
    chainVerifier,
    expected: {
      status: result.status,
      verificationLevel: result.verificationLevel,
      reason: result.reason,
      tcbStatus: result.tcbStatus,
      failedRequiredChecks: result.checks.filter((c) => c.required && !c.passed).map((c) => c.name),
      unmetAdvisoryChecks: result.checks.filter((c) => !c.required && !c.passed).map((c) => c.name)
    }
  };
});

const document = {
  _readme: [
    "Complete hop 1 verdicts, loaded identically by the JS and Python suites.",
    "",
    "HOW TO READ A CASE. Start from `base`, apply the case's `evidence` overrides,",
    "delete the keys in `evidenceRemoved`, and do the same for `policy` and",
    "`expectations`. The merge is shallow, and the removal lists exist because JSON",
    "cannot express 'absent' while an evidence document with no issued_at_ms is a case",
    "that has to be reachable. The generator asserts that merging reproduces the exact",
    "bytes it verified, so the rule is pinned rather than assumed.",
    "",
    "attestation.json does this for hop 2. Without an equivalent here, the two",
    "languages agreed about the binding digest and the quote parse but nothing pinned",
    "the VERDICT: which checks are required, what a failure is called, and which single",
    "check a given tamper is supposed to fail. A change landing in one language and not",
    "the other could pass both suites.",
    "",
    "Each case carries a COMPLETE evidence document, so both languages verify the same",
    "bytes rather than each rebuilding a fixture and hoping the two agree. Most cases",
    "change exactly one thing from the baseline, and the expectation names the exact",
    "check that change is supposed to fail. Cases that PASS are as load-bearing as the",
    "failures: they are what stops a change from making everything fail.",
    "",
    "`chainVerifier` is a stub each language constructs locally from the recorded",
    "{verified, tcbStatus}, because a verifier is code and cannot be serialized. It is",
    "how the TCB cases are reachable without an engine.",
    "",
    "`observedTlsSpki.supplied` distinguishes 'not observed' from 'observed and there",
    "is none'. Python has no `undefined`, so the two are separated explicitly rather",
    "than collapsed into null, which would silently turn an unmet gap into a mismatch.",
    "",
    "Regenerate with: npx tsx scripts/gen-gateway-verdict-vectors.ts (in js/confidential).",
    "A changed expectation is a changed security decision, not a test fixup."
  ],
  bindingVersion: GATEWAY_BINDING_VERSION,
  base: {
    evidence: baseEvidence,
    policy: basePolicy,
    expectations: baseExpectations
  },
  cases
};

writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`);
const failures = cases.filter((c) => c.expected.status === "failed").length;
console.log(`wrote ${out}`);
console.log(`${cases.length} cases: ${cases.length - failures} pass, ${failures} fail`);
