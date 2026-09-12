// Loader for the operator-reviewed TEE/E2EE measurement policy. `measurements.json`
// is a byte-identical, CI-parity-gated copy of the monorepo's canonical
// `shared/measurements.json`, which holds the same policy AnonRouter's gateway
// enforces server-side. Static measurements remain code-reviewed pins. Tinfoil is
// different by design: its fixed policy pins the official signed-release authority
// and repository while the official verifier checks the current release output.
//
// Every verifier and E2EE transport reads its policy through this one loader, so
// there is a single source of truth for which enclave measurements and endpoints
// are acceptable.

import measurementsJson from "./measurements.json" with { type: "json" };

/** A single accepted TDX measurement identity (MRTD + RTMR0..3). NEAR entries
 *  additionally carry the pinned compose document digest + provenance. */
export interface TdxMeasurementEntry {
  name: string;
  mrTd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  composeSha256?: string;
  composeRepository?: string;
  composeRepositoryCommit?: string;
  composeRepositoryPath?: string;
}

/** The one Tinfoil release authority accepted by the AnonRouter packages.
 *
 *  Only `configRepo` is re-derived from evidence: the Tinfoil verifier compares
 *  it against the repository the verification document names, so a different
 *  repository fails closed. `authority`, `releaseSelection` and
 *  `requireTaggedRelease` are LABELS recording which Tinfoil workflow this
 *  package was reviewed against, and they pin this file against a silent edit.
 *  Nothing here re-checks them: the document carries no Fulcio identity or
 *  workflow ref to check them against, and those guarantees belong to the
 *  official verifier's own `verifyCode` / `fetchDigest` steps.
 *
 *  Replaces the `TinfoilAcceptedRelease` entry type used through 0.1.1, which
 *  described a per-release fingerprint allowlist that no longer exists. */
export interface TinfoilProviderAuthority {
  authority: "github-actions-sigstore";
  configRepo: "tinfoilsh/confidential-model-router";
  releaseSelection: "latest";
  requireTaggedRelease: true;
}

/** The provider-neutral measurement policy the verifier binds evidence against.
 *  `accepted` is provider-specific and interpreted only by that provider verifier. */
export interface MeasurementPolicy {
  source: string;
  version: string;
  accepted: unknown;
}

interface RawMeasurementPolicy {
  source?: string;
  version?: string;
  kind?: string;
  accepted?: unknown;
}

interface RawMeasurements {
  schemaVersion?: number;
  tdxTeeType?: number;
  providers?: {
    chutes?: { endpointIdentity?: string; measurementPolicy?: RawMeasurementPolicy | null };
    tinfoil?: { endpointIdentity?: string; measurementPolicy?: RawMeasurementPolicy | null };
    venice?: { endpointIdentity?: string; measurementPolicy?: RawMeasurementPolicy | null };
    "near-ai"?: {
      byModel?: Record<string, { endpointIdentity?: string; measurementPolicy?: RawMeasurementPolicy | null }>;
    };
  };
}

const DATA = measurementsJson as unknown as RawMeasurements;

/** The Intel TDX `tee_type` value the pins were reviewed for (0x81 / 129). */
export const TDX_TEE_TYPE: number = typeof DATA.tdxTeeType === "number" ? DATA.tdxTeeType : 0x00000081;

function toPolicy(raw: RawMeasurementPolicy | null | undefined): MeasurementPolicy | undefined {
  if (!raw || typeof raw.source !== "string" || typeof raw.version !== "string") return undefined;
  return { source: raw.source, version: raw.version, accepted: raw.accepted ?? [] };
}

/**
 * Resolve the pinned measurement policy for a route, or undefined when none is
 * pinned (Venice binds on the signing key / workload keyset, not a measurement
 * allowlist, so it returns undefined by design). `near-ai` is keyed per upstream
 * model under `providers["near-ai"].byModel[model]`.
 */
export function pinnedMeasurementPolicyFor(provider: string, model: string): MeasurementPolicy | undefined {
  const providers = DATA.providers ?? {};
  if (provider === "chutes") return toPolicy(providers.chutes?.measurementPolicy);
  if (provider === "tinfoil") return toPolicy(providers.tinfoil?.measurementPolicy);
  if (provider === "venice") return toPolicy(providers.venice?.measurementPolicy);
  if (provider === "near-ai") return toPolicy(providers["near-ai"]?.byModel?.[model]?.measurementPolicy);
  return undefined;
}

/**
 * Resolve the operator-pinned endpoint identity (direct enclave host) for a route,
 * or undefined when the route is not host-pinned. Only `near-ai` direct routes are
 * host-pinned in policy today.
 */
export function pinnedEndpointIdentityFor(provider: string, model: string): string | undefined {
  const providers = DATA.providers ?? {};
  if (provider === "near-ai") {
    const identity = providers["near-ai"]?.byModel?.[model]?.endpointIdentity;
    return typeof identity === "string" ? identity : undefined;
  }
  // Other providers (e.g. tinfoil) carry a single reviewed endpoint identity.
  const entry = (providers as Record<string, { endpointIdentity?: string }>)[provider];
  return typeof entry?.endpointIdentity === "string" ? entry.endpointIdentity : undefined;
}

/** The raw, parsed policy document (for advanced callers that want the full pins). */
export function measurementPolicyDocument(): RawMeasurements {
  return DATA;
}
