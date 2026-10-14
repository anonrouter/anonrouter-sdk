import { createReleasePolicyV3Source, type ReleasePolicyV3Source } from "./release-v3.js";
import type { GatewayAttestationEvidence, GatewayVerificationResult, TdxChainVerifier, TdxChainVerifierFactory } from "./verify.js";

export interface VerifyContentNodeOptions {
  /** Default https://api.anonrouter.ai. Must be an origin the policy source authorizes. */
  origin?: string;
  /** Default: the packaged production owner root and feed (`createReleasePolicyV3Source()`). */
  policySource?: ReleasePolicyV3Source;
  /** Default: the reviewed native DCAP engine (`createAnonRouterDcapVerifier()`). */
  chainVerifier?: TdxChainVerifier | TdxChainVerifierFactory;
  signal?: AbortSignal;
}

export interface VerifyContentNodeResult {
  origin: string;
  policy: {
    origin: "signed-release-policy-v3";
    source: string;
    version: string;
    sequence: number;
    payloadSha256: string;
    ownerRootSha256: string;
    deploymentId: string;
  };
  /**
   * status "ok" only when every required check passed on the retained socket.
   * A failed verdict is returned (not thrown) when evidence was fetched and
   * judged; transport, policy-feed and configuration failures throw.
   */
  verdict: GatewayVerificationResult;
  /** The evidence document, only for an accepted verdict. */
  rawEvidence: GatewayAttestationEvidence | null;
}

/** Credential-free, read-only GCP attestation with a fresh nonce on one TLS socket.
 * Node only. The socket is closed after verification; inference must use the
 * client's required gatewayConnectionBinding to retain its own verified socket. */
export async function verifyContentNode(options: VerifyContentNodeOptions = {}): Promise<VerifyContentNodeResult> {
  const runtime = globalThis as unknown as { process?: { versions?: { node?: string } }; window?: { document?: unknown } };
  if (!runtime.process?.versions?.node || runtime.window?.document) throw new Error("Content-node verification requires native Node TLS");
  const origin = options.origin ?? "https://api.anonrouter.ai";
  const source = options.policySource ?? createReleasePolicyV3Source();
  // Variable specifiers keep native Node dependencies outside browser bundles.
  const retainedSpecifier = new URL("./retained-operation-node.js", import.meta.url).href;
  const { openRetainedGatewayOperation, RetainedGatewayError } = await import(retainedSpecifier) as typeof import("./retained-operation-node.js");
  let chainVerifier = options.chainVerifier;
  if (!chainVerifier) {
    const dcapSpecifier = new URL("./dcap/engine.js", import.meta.url).href;
    const { createAnonRouterDcapVerifier } = await import(dcapSpecifier) as typeof import("./dcap/engine.js");
    chainVerifier = createAnonRouterDcapVerifier();
  }
  let approval = await source.resolve(origin, options.signal);
  const provenance = () => ({ origin: "signed-release-policy-v3" as const, source: approval.policy.source,
    version: approval.policy.version, sequence: approval.sequence, payloadSha256: approval.payloadSha256,
    ownerRootSha256: approval.release.ownerRootSha256, deploymentId: approval.release.deploymentId });
  let connection: Awaited<ReturnType<typeof openRetainedGatewayOperation>>;
  try {
    connection = await openRetainedGatewayOperation({ origin, policy: approval.policy, chainVerifier,
      approvalExpiresAtMs: approval.expiresAtMs, ...(options.signal ? { signal: options.signal } : {}),
      refreshPolicy: async signal => {
        approval = await source.resolve(origin, signal, true);
        return { policy: approval.policy, approvalExpiresAtMs: approval.expiresAtMs };
      } });
  } catch (error) {
    if (error instanceof RetainedGatewayError && error.code === "untrusted" && error.verdict) {
      return { origin, policy: provenance(), verdict: error.verdict, rawEvidence: null };
    }
    throw error;
  }
  try {
    return { origin, policy: provenance(), verdict: connection.verdict, rawEvidence: connection.rawEvidence };
  } finally { connection.close(); }
}
