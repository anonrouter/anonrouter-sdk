// Optional Node-only implementation. The browser/main entry loads it through a
// nonliteral dynamic import only after the caller explicitly requests binding.
import { ConfidentialError } from "../errors.js";
import type { FetchLike } from "../transport/types.js";
import type { GatewayMeasurementPolicy } from "./policy.js";
import type { GatewayVerificationResult } from "./verify.js";
import { createSpkiBoundGatewayTransport } from "./transport-node.js";

export interface VerifiedGatewayConnection {
  readonly identity: Readonly<{ origin: string; tlsSpkiSha256: string; appId: string; instanceId: string; composeHash: string; expiresAtMs: number }>;
  readonly fetch: FetchLike;
  assertDispatchAllowed(): void;
  close(): void;
}

export function createVerifiedGatewayConnection(input: {
  origin: string;
  verdict: GatewayVerificationResult;
  policy: GatewayMeasurementPolicy;
  evidenceIssuedAtMs: number;
  approvalExpiresAtMs?: number;
  signal?: AbortSignal;
}): VerifiedGatewayConnection {
  const binding = input.verdict.binding;
  if (input.verdict.status !== "ok" || input.verdict.verificationLevel !== "hardware-verified"
      || input.verdict.tcbStatus !== "UpToDate" || !binding || binding.origin !== input.origin
      || binding.transport !== "in-tee-tls" || typeof binding.tls_spki_sha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(binding.tls_spki_sha256)
      || !input.verdict.checks.some(check => check.name === "quote_signature_chain" && check.passed)
      || input.verdict.checks.some(check => check.required && !check.passed)
      || !Number.isSafeInteger(input.evidenceIssuedAtMs)) {
    throw new ConfidentialError("attestation_untrusted", "A fully verified gateway identity is required for connection binding.");
  }
  const expiry = Math.min(input.evidenceIssuedAtMs + input.policy.maxEvidenceAgeMs, input.approvalExpiresAtMs ?? Infinity);
  const identity = Object.freeze({ origin: input.origin, tlsSpkiSha256: binding.tls_spki_sha256,
    appId: binding.app_id, instanceId: binding.instance_id, composeHash: binding.compose_hash, expiresAtMs: expiry });
  const operationSignal = input.signal;
  let closed = false;
  function assertDispatchAllowed(): void {
    if (closed || operationSignal?.aborted) throw new ConfidentialError("cancelled", "The bound gateway operation was cancelled.");
    if (Date.now() >= expiry) throw new ConfidentialError("measurement_untrusted", "The verified gateway approval or evidence expired before dispatch.");
  }
  assertDispatchAllowed();
  const transport = createSpkiBoundGatewayTransport({ origin: identity.origin,
    expectedTlsSpkiSha256: identity.tlsSpkiSha256, beforeHttpDispatch: assertDispatchAllowed });
  return Object.freeze({ identity, assertDispatchAllowed,
    fetch: async (url: string, init?: RequestInit) => {
      assertDispatchAllowed();
      const signal = operationSignal && init?.signal ? AbortSignal.any([operationSignal, init.signal]) : operationSignal ?? init?.signal;
      return transport.fetch(url, { ...init, ...(signal ? { signal } : {}) });
    },
    close() { if (closed) return; closed = true; transport.close(); }
  });
}
