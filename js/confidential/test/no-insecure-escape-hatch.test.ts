// There is no way to accidentally turn verification off.
//
// Every SDK grows an escape hatch eventually: a NODE_ENV check, an
// ANONROUTER_INSECURE=1, a "skip in tests" branch. Each one is a switch an
// attacker who can set an environment variable, or a developer copying a
// deployment config, can flip to make a failing verdict pass. This file asserts
// the absence of that whole class, which is a property worth testing precisely
// because it is invisible until somebody adds one.
//
// The three deliberate opt-ins are tested here too, from the other direction:
// each must still require its explicit argument, and none may be reachable
// through the environment.

import { describe, expect, it } from "vitest";
import { loadGatewayPolicy, pinnedGatewayPolicyFor } from "../src/gateway/policy.js";
import { verifyGatewayAttestation } from "../src/gateway/verify.js";
import { createClient } from "../src/client.js";
import { ConfidentialError } from "../src/errors.js";
import { runCli, EXIT_USAGE, type CliIo } from "../src/cli/run.js";
import vectors from "../../../shared/vectors/gateway-verdicts.json" with { type: "json" };

/** Names an escape hatch would plausibly be spelled. None of these may do anything. */
const HOSTILE_ENV: Record<string, string> = {
  NODE_ENV: "test",
  CI: "true",
  ANONROUTER_INSECURE: "1",
  ANONROUTER_SKIP_VERIFY: "1",
  ANONROUTER_SKIP_ATTESTATION: "1",
  ANONROUTER_ALLOW_CANDIDATE: "1",
  ANONROUTER_ALLOW_INSECURE_HTTP: "1",
  ANONROUTER_DISABLE_TLS_CHECK: "1",
  ANONROUTER_REQUIRE_HARDWARE: "0",
  ANONROUTER_TRUST_GATEWAY: "1",
  ANONROUTER_DEV: "1",
  ANONROUTER_TEST_MODE: "1"
};

function withEnv<T>(overrides: Record<string, string>, run: () => T): T {
  const saved = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(overrides)) {
    saved.set(key, process.env[key]);
    process.env[key] = value;
  }
  try {
    return run();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function capture(): CliIo & { stdout: string; stderr: string } {
  const sink = {
    stdout: "",
    stderr: "",
    out(text: string) { sink.stdout += text; },
    err(text: string) { sink.stderr += text; }
  };
  return sink;
}

const POLICY = loadGatewayPolicy({
  source: "escape-hatch-probe",
  version: "1",
  origins: ["https://x.invalid"],
  appIds: ["aa"],
  composeHashes: ["ab".repeat(32)],
  releaseIds: ["r"],
  requireInTeeTls: true,
  requirePrivateLogs: true,
  requireDigestPinnedImages: true,
  requireHardwareVerified: true,
  acceptableTcbStatuses: ["UpToDate"],
  requireEvidenceExpiry: true,
  maxEvidenceAgeMs: 300_000
});

describe("no environment variable can weaken a verdict", () => {
  it("garbage evidence fails identically with and without every plausible hatch set", () => {
    const evidence = { binding: null, quote: "zz", event_log: "[]", app_compose: "" };
    const expectations = { nonce: "0".repeat(64), origin: "https://x.invalid", policy: POLICY, now: 1 };

    const clean = verifyGatewayAttestation(evidence, expectations);
    const hostile = withEnv(HOSTILE_ENV, () => verifyGatewayAttestation(evidence, expectations));

    expect(clean.status).toBe("failed");
    expect(hostile.status).toBe("failed");
    // Byte-identical, not merely both failing: a hatch that changed which checks
    // ran would be a difference worth seeing even if the outcome happened to match.
    expect(JSON.stringify(hostile)).toBe(JSON.stringify(clean));
  });

  it("a policy requiring hardware verification still fails closed with no engine", () => {
    // The single most tempting hatch: "it is fine, we are in CI". It is not fine.
    // This uses the shared vectors' base document, which is otherwise valid, so
    // the run actually REACHES the chain check rather than failing before it.
    const base = vectors.base as unknown as {
      evidence: Record<string, unknown>;
      policy: Record<string, unknown>;
      expectations: Record<string, unknown>;
    };
    const policy = loadGatewayPolicy({ ...base.policy, requireHardwareVerified: true });
    const result = withEnv(HOSTILE_ENV, () => verifyGatewayAttestation(base.evidence as never, {
      nonce: base.expectations.nonce as string,
      origin: base.expectations.origin as string,
      policy,
      now: base.expectations.nowMs as number
    }));
    const chain = result.checks.find((c) => c.name === "quote_signature_chain")!;
    expect(chain.required).toBe(true);
    expect(chain.passed).toBe(false);
    expect(result.status).toBe("failed");

    // The same document under a policy that does NOT require it still passes, so
    // the failure above is the requirement biting and not the document being bad.
    const relaxed = verifyGatewayAttestation(base.evidence as never, {
      nonce: base.expectations.nonce as string,
      origin: base.expectations.origin as string,
      policy: loadGatewayPolicy(base.policy),
      now: base.expectations.nowMs as number
    });
    expect(relaxed.status).toBe("ok");
    expect(relaxed.verificationLevel).toBe("provider-attested");
  });
});

describe("the deliberate opt-ins stay deliberate", () => {
  it("a candidate pin does not resolve through the environment", () => {
    const origin = "https://api.private.anonrouter.ai";
    expect(withEnv(HOSTILE_ENV, () => pinnedGatewayPolicyFor(origin))).toBeUndefined();
    // ...and still resolves when the CALLER asks, so this is about who decides.
    expect(pinnedGatewayPolicyFor(origin, { allowCandidate: true })).not.toBeUndefined();
  });

  it("a plaintext remote origin is refused however the environment is set", () => {
    // Over plaintext the API key travels in the clear and the origin a quote binds
    // cannot mean anything, so an attested route would become decorative.
    withEnv(HOSTILE_ENV, () => {
      expect(() => createClient({ baseUrl: "http://api.anonrouter.ai", apiKey: "k" }))
        .toThrow(ConfidentialError);
      // Even the explicit opt-in does not extend past loopback.
      expect(() => createClient({ baseUrl: "http://api.anonrouter.ai", apiKey: "k", allowInsecureHttp: true }))
        .toThrow(ConfidentialError);
      // Loopback plus the explicit flag is the one accepted combination.
      expect(() => createClient({ baseUrl: "http://127.0.0.1:3000", apiKey: "k", allowInsecureHttp: true }))
        .not.toThrow();
      // ...and the flag is still required for it.
      expect(() => createClient({ baseUrl: "http://127.0.0.1:3000", apiKey: "k" }))
        .toThrow(ConfidentialError);
    });
  });

  it("the command still refuses hardware_verified without --dcap, whatever the environment says", async () => {
    const io = capture();
    const code = await withEnv(HOSTILE_ENV, () =>
      runCli(["gateway", "--origin", "https://x.example", "--require", "hardware_verified"], io));
    expect(code).toBe(EXIT_USAGE);
    expect(io.stderr).toContain("needs --dcap");
  });

  it("the command still needs --allow-candidate for a candidate pin", async () => {
    // With the flag absent the origin has no resolvable policy, which is
    // `unavailable`: we could not look, rather than we looked and it passed.
    const io = capture();
    const code = await withEnv(HOSTILE_ENV, () =>
      runCli(["gateway", "--origin", "https://api.private.anonrouter.ai", "--compact", "--no-tls-check"], io));
    expect(code).not.toBe(0);
    const document = JSON.parse(io.stdout);
    expect(document.outcome.met).toBe(false);
    expect(String(document.gateway.reason)).toContain("pinned gateway policy");
  }, 60_000);
});

describe("the source contains no environment-driven verification branch", () => {
  it("the pure verifier and the policy loader never read process.env", async () => {
    // A structural assertion, because the behavioural ones above can only cover
    // the names someone thought to try. These two modules decide whether a verdict
    // passes; neither has any business reading the environment.
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, resolve } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    for (const relative of ["../src/gateway/verify.ts", "../src/gateway/policy.ts", "../src/verify/state.ts", "../src/verify/route.ts"]) {
      const source = readFileSync(resolve(here, relative), "utf8");
      expect(source, `${relative} reads the environment`).not.toContain("process.env");
    }
  });
});
