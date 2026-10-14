import { createReleasePolicyV3Source, type ReleasePolicyV3Source } from "./release-v3.js";
import type { TdxChainVerifier, TdxChainVerifierFactory } from "./verify.js";

export interface VerifyContentNodeOptions {
  origin?: string;
  policySource?: ReleasePolicyV3Source;
  chainVerifier?: TdxChainVerifier | TdxChainVerifierFactory;
  signal?: AbortSignal;
}

/** Credential-free, read-only GCP attestation with a fresh nonce on one TLS socket.
 * Node only. The socket is closed after verification; inference must use the
 * client's required gatewayConnectionBinding to retain its own verified socket. */
export async function verifyContentNode(options: VerifyContentNodeOptions = {}) {
  const runtime = globalThis as unknown as { process?: { versions?: { node?: string } }; window?: { document?: unknown } };
  if (!runtime.process?.versions?.node || runtime.window?.document) throw new Error("Content-node verification requires native Node TLS");
  const origin = options.origin ?? "https://api.anonrouter.ai";
  const source = options.policySource ?? createReleasePolicyV3Source();
  // Variable specifiers keep native Node dependencies outside browser bundles.
  const retainedSpecifier = new URL("./retained-operation-node.js", import.meta.url).href;
  const { openRetainedGatewayOperation } = await import(retainedSpecifier) as typeof import("./retained-operation-node.js");
  let chainVerifier = options.chainVerifier;
  if (!chainVerifier) {
    const dcapSpecifier = new URL("./dcap/engine.js", import.meta.url).href;
    const { createAnonRouterDcapVerifier } = await import(dcapSpecifier) as typeof import("./dcap/engine.js");
    chainVerifier = createAnonRouterDcapVerifier();
  }
  let approval = await source.resolve(origin, options.signal);
  const connection = await openRetainedGatewayOperation({ origin, policy: approval.policy, chainVerifier,
    approvalExpiresAtMs: approval.expiresAtMs, signal: options.signal,
    refreshPolicy: async signal => {
      approval = await source.resolve(origin, signal, true);
      return { policy: approval.policy, approvalExpiresAtMs: approval.expiresAtMs };
    } });
  try {
    return { origin, policy: { origin: "signed-release-policy-v3" as const, source: approval.policy.source,
      version: approval.policy.version, sequence: approval.sequence, payloadSha256: approval.payloadSha256,
      ownerRootSha256: approval.release.ownerRootSha256, deploymentId: approval.release.deploymentId },
    verdict: connection.verdict, rawEvidence: connection.rawEvidence };
  } finally { connection.close(); }
}
