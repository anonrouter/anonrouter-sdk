// Real local TLS + actual compiled client/crypto/structural verifier wiring.
// Intel DCAP is an explicit synthetic factory boundary; this suite does NOT
// constitute hardware verification, production acceptance or paid inference.
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer as httpsServer } from "node:https";
import { createServer as httpServer } from "node:http";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash, X509Certificate } from "node:crypto";
import type { CreateClientOptions } from "../dist/client.js";
const packageRoot = process.env.SDK_BOUND_CLIENT_PACKAGE_ROOT;
const { createClient }: typeof import("../dist/client.js") = await import(
  packageRoot ? pathToFileURL(join(packageRoot, "dist/client.js")).href : new URL("../dist/client.js", import.meta.url).href);
const { createVerifiedGatewayConnection }: typeof import("../dist/gateway/connection-session.js") = await import(
  packageRoot ? pathToFileURL(join(packageRoot, "dist/gateway/connection-session.js")).href : new URL("../dist/gateway/connection-session.js", import.meta.url).href);
import { gatewayBindingHash, GATEWAY_BINDING_VERSION } from "../src/gateway/binding.js";
import { loadGatewayPolicy } from "../src/gateway/policy.js";
import { buildAppCompose, buildSyntheticEventLog, buildSyntheticGcpQuote, buildSyntheticTdxQuote, buildVmConfig,
  SYNTHETIC_GCP_BOOT_KEY, SYNTHETIC_GCP_INSTANCE_ID, SYNTHETIC_GCP_REGISTERS, SYNTHETIC_GCP_VERITY_ROOT,
  SYNTHETIC_MR_CONFIG_ID, SYNTHETIC_OS_IMAGE_HASH } from "./helpers/gateway-fixtures.js";
import { createVeniceMockEnclave } from "./helpers/mock-enclaves.js";

const fixture = process.env.SDK_BOUND_CLIENT_FIXTURE!;
const keys = Object.fromEntries(["a", "b"].map(slot => [slot, {
  key: readFileSync(join(fixture, `${slot}.key`)), cert: readFileSync(join(fixture, `${slot}.pem`))
}])) as Record<string, { key: Buffer; cert: Buffer }>;
const fingerprint = (raw: Buffer) => createHash("sha256").update(new X509Certificate(raw).publicKey.export({ type: "spki", format: "der" })).digest("hex");
const pins = Object.fromEntries(Object.entries(keys).map(([slot, key]) => [slot, fingerprint(key.cert)]));
const APP = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE = "fedcba9876543210fedcba9876543210fedcba98";
const KMS = "fe".repeat(32);
const RELEASE = "sdk-bound-client@synthetic";
const MODEL = "venice-uncensored";
const compose = buildAppCompose();
const log = buildSyntheticEventLog({ appId: APP, instanceId: INSTANCE, composeHash: compose.hash, keyProviderId: KMS });
const cleanup: Array<() => Promise<void>> = [];
// Replaces the served evidence for one test; reset after every test.
let evidenceOverride: ((origin: string, nonce: string, slot: string) => unknown) | null = null;
afterEach(async () => { evidenceOverride = null; vi.restoreAllMocks(); vi.unstubAllGlobals(); for (const close of cleanup.splice(0)) await close(); });

function policy(origin: string) {
  return loadGatewayPolicy({ source: "synthetic-client-wiring-policy", version: "1", origins: [origin],
    appIds: [APP], composeHashes: [compose.hash], releaseIds: [RELEASE], keyProviderId: KMS,
    requireInTeeTls: true, requirePrivateLogs: true, requireDigestPinnedImages: true,
    requireHardwareVerified: true, requireEvidenceExpiry: true, maxEvidenceAgeMs: 300_000,
    acceptableTcbStatuses: ["UpToDate"], platform: { mrTd: ["00".repeat(48)], mrConfigId: [SYNTHETIC_MR_CONFIG_ID],
      rtmr0: [log.rtmr0], rtmr1: [log.rtmr1], rtmr2: [log.rtmr2], osImageHash: [SYNTHETIC_OS_IMAGE_HASH] } });
}
function evidence(origin: string, nonce: string, slot: string) {
  const binding = { v: GATEWAY_BINDING_VERSION, nonce, app_id: APP, instance_id: INSTANCE,
    compose_hash: compose.hash, release_id: RELEASE, origin, key_alg: "x25519" as const,
    public_key: "ab".repeat(32), transport: "in-tee-tls" as const, tls_spki_sha256: pins[slot]! };
  return { binding, quote: buildSyntheticTdxQuote({ reportDataHex: gatewayBindingHash(binding),
    rtmr0: log.rtmr0, rtmr1: log.rtmr1, rtmr2: log.rtmr2, rtmr3: log.rtmr3 }),
    event_log: JSON.stringify(log.events), app_compose: compose.manifest, vm_config: buildVmConfig(), issued_at_ms: Date.now() };
}
// Explicitly mock ONLY the native Intel verifier port, bound to the exact quote.
// All nonce/origin/policy/event/compose/SPKI transport checks execute for real.
const syntheticNativeBoundary = {
  async prepare(quote: string) { return { implementation: "synthetic-native-test-boundary-NOT-Intel",
    verifyChain(candidate: string) { return { verified: candidate === quote, tcbStatus: "UpToDate" }; } }; }
};

async function topology(options: { start?: string; switchOnEvidence?: boolean; holdAttestationTickets?: boolean;
  expireAfterProviderEvidence?: boolean; expireAfterPaidTicket?: boolean; paidExpiryAdvanceMs?: number; streamDelayMs?: number; dnsSwitch?: boolean; paidClose?: boolean;
  initialResets?: number; onInitialConnection?: () => void } = {}) {
  let active = options.start ?? "a";
  const observed = { gateway: 0, nonces: [] as string[], attTickets: 0, paidTickets: 0,
    content: [] as Array<{ path: string; slot: string; body: string; authorization?: string }>,
    bytes: { a: 0, b: 0 }, handshakes: { a: 0, b: 0 }, connections: 0, lookups: 0, controlBodies: [] as string[] };
  const enclave = createVeniceMockEnclave(MODEL);
  const sockets = new Set<import("node:net").Socket>();
  let contentOrigin = "";
  let releaseTickets!: () => void;
  const ticketGate = new Promise<void>(resolve => { releaseTickets = resolve; });
  const clock = options.expireAfterProviderEvidence || options.expireAfterPaidTicket ? vi.spyOn(Date, "now") : null;
  const initial = Date.now();
  if (clock) clock.mockReturnValue(initial);
  let dnsTarget = "127.0.0.1";
  if (options.dnsSwitch) {
    const originalLookup = dns.lookup;
    vi.spyOn(dns, "lookup").mockImplementation(((name: string, lookupOptions: unknown, callback?: unknown) => {
      if (name !== "localhost") return (originalLookup as (...args: unknown[]) => unknown)(name, lookupOptions, callback);
      observed.lookups++;
      const cb = (typeof lookupOptions === "function" ? lookupOptions : callback) as (error: null, address: unknown, family?: number) => void;
      const family = dnsTarget === "::1" ? 6 : 4;
      const all = typeof lookupOptions === "object" && lookupOptions !== null && "all" in lookupOptions && lookupOptions.all;
      queueMicrotask(() => all ? cb(null, [{ address: dnsTarget, family }]) : cb(null, dnsTarget, family));
    }) as typeof dns.lookup);
  }
  const handler: import("node:http").RequestListener = async (req, res) => {
    const slot = fingerprint((req.socket as import("node:tls").TLSSocket).getCertificate().raw!) === pins.a ? "a" : "b";
    const url = new URL(req.url!, contentOrigin);
    let body = "";
    for await (const chunk of req) body += chunk;
    if (url.pathname === "/v1/gateway/attestation") {
      observed.gateway++;
      const nonce = url.searchParams.get("nonce")!;
      observed.nonces.push(nonce);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(evidenceOverride ? evidenceOverride(contentOrigin, nonce, slot) : evidence(contentOrigin, nonce, slot)));
      if (options.dnsSwitch) dnsTarget = "::1";
      else if (options.switchOnEvidence) { active = "b"; content.setSecureContext(keys.b); }
      return;
    }
    if (options.paidClose && url.pathname !== "/v1/tee/attestation") res.setHeader("connection", "close");
    observed.content.push({ path: url.pathname, slot, body,
      ...(req.headers.authorization ? { authorization: req.headers.authorization } : {}) });
    if (url.pathname === "/v1/tee/attestation") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(enclave.attestationResponse(JSON.parse(body).nonce)));
      if (options.expireAfterProviderEvidence) clock!.mockReturnValue(initial + 300_001);
    } else if (url.pathname === "/v1/chat/completions") {
      const response = enclave.handleInference({ body, headers: req.headers as Record<string, string> }).response;
      res.setHeader("content-type", response.headers.get("content-type")!);
      const wire = await response.text();
      if (options.streamDelayMs) {
        for (const event of wire.split("\n\n")) {
          if (!event || res.destroyed) break;
          res.write(event + "\n\n");
          await new Promise(resolve => setTimeout(resolve, options.streamDelayMs));
        }
        if (!res.destroyed) res.end();
      } else res.end(wire);
    } else if (url.pathname === "/v1/images/generations") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ created: 1, data: [{ b64_json: "aGVsbG8=", mime_type: "image/png" }] }));
    } else if (url.pathname === "/v1/audio/speech") {
      res.setHeader("content-type", "audio/mpeg");
      res.end(Buffer.from([1, 2, 3]));
    } else { res.writeHead(404); res.end(); }
  };
  const content = httpsServer(keys[active], handler);
  content.on("connection", socket => {
    observed.connections++;
    if (observed.connections <= (options.initialResets ?? 0)) {
      socket.resetAndDestroy(); options.onInitialConnection?.();
    }
  });
  const spare = options.dnsSwitch ? httpsServer(keys.b, handler) : undefined;
  const trackContent = (server: ReturnType<typeof httpsServer>) => server.on("secureConnection", socket => {
    sockets.add(socket); socket.once("close", () => sockets.delete(socket));
    const slot = fingerprint(socket.getCertificate().raw!) === pins.a ? "a" : "b";
    observed.handshakes[slot]++;
    socket.on("data", chunk => { observed.bytes[slot] += chunk.length; });
  });
  trackContent(content); if (spare) trackContent(spare);
  content.keepAliveTimeout = 600_000; if (spare) spare.keepAliveTimeout = 600_000;
  content.on("tlsClientError", () => {}); spare?.on("tlsClientError", () => {});
  const control = httpServer(async (req, res) => {
    let body = ""; for await (const chunk of req) body += chunk;
    observed.controlBodies.push(body);
    res.setHeader("content-type", "application/json");
    if (req.url === "/v1/inference/attestation-tickets") {
      observed.attTickets++;
      if (options.holdAttestationTickets) {
        if (observed.attTickets === 2) releaseTickets();
        await ticketGate;
      }
      res.end(JSON.stringify({ ticket: "synthetic-attestation" }));
    } else if (req.url === "/v1/inference/tickets") {
      observed.paidTickets++;
      res.end(JSON.stringify({ ...JSON.parse(body), ticket: `synthetic-paid-${observed.paidTickets}` }));
      if (options.expireAfterPaidTicket) clock!.mockReturnValue(initial + (options.paidExpiryAdvanceMs ?? 300_001));
    } else { res.writeHead(404); res.end(); }
  });
  control.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise<void>(resolve => content.listen(0, "127.0.0.1", resolve));
  if (spare) await new Promise<void>(resolve => spare.listen({ host: "::1", port: (content.address() as import("node:net").AddressInfo).port, ipv6Only: true }, resolve));
  await new Promise<void>(resolve => control.listen(0, "127.0.0.1", resolve));
  contentOrigin = `https://${options.dnsSwitch ? "localhost" : "127.0.0.1"}:${(content.address() as import("node:net").AddressInfo).port}`;
  const controlOrigin = `http://127.0.0.1:${(control.address() as import("node:net").AddressInfo).port}`;
  cleanup.push(async () => {
    for (const socket of sockets) socket.destroy();
    await Promise.all([new Promise<void>(resolve => content.close(() => resolve())), new Promise<void>(resolve => control.close(() => resolve())), ...(spare ? [new Promise<void>(resolve => spare.close(() => resolve()))] : [])]);
  });
  const clientOptions: CreateClientOptions = { inferenceBaseUrl: contentOrigin, controlBaseUrl: controlOrigin,
    apiKey: "synthetic-control-only-key", allowInsecureHttp: true,
    gatewayConnectionBinding: { mode: "required", verification: { policy: policy(contentOrigin), chainVerifier: syntheticNativeBoundary } } };
  return { observed, contentOrigin, controlOrigin, clientOptions, client: createClient(clientOptions) };
}
const chat = (signal?: AbortSignal) => ({ model: MODEL, provider: "venice", messages: [{ role: "user" as const, content: "synthetic-content-canary" }], maxOutputTokens: 32, ...(signal ? { signal } : {}) });

describe("required gateway content connection wiring — synthetic native port, real TLS", () => {
  it("initial TLS reset retries one fresh preparation before any ticket or HTTP", async () => {
    const t = await topology({ initialResets: 1 });
    expect((await t.client.chat(chat())).content).toBe("Hello E2EE");
    expect(t.observed.connections).toBe(2);
    expect(t.observed.gateway).toBe(1);
    expect(t.observed.attTickets).toBe(1); expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.handshakes.a).toBe(1); expect(t.observed.content).toHaveLength(2);
  });
  it("repeated initial reset stops after two sockets with zero tickets/content", async () => {
    const t = await topology({ initialResets: 10 });
    await expect(t.client.chat(chat())).rejects.toThrow();
    expect(t.observed.connections).toBe(2); expect(t.observed.gateway).toBe(0);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0);
    expect(t.observed.content).toHaveLength(0); expect(t.observed.handshakes.a).toBe(0);
  });
  it("fresh preparation resolves policy again after the joined initial reset", async () => {
    const t = await topology({ initialResets: 1 }); let resolutions = 0;
    const issuedAtMs = Date.now();
    const client = createClient({ ...t.clientOptions,
      gatewayPolicyUpdates: { async resolve() {
        const current = policy(t.contentOrigin); resolutions++;
        if (resolutions === 1) current.composeHashes = ["ff".repeat(32)];
        return { policy: current, sequence: resolutions, payloadSha256: "ab".repeat(32),
          authority: "synthetic-source-NOT-signed", manifestSha256: "cd".repeat(32), issuedAtMs,
          expiresAtMs: issuedAtMs + 10000, acceptedKeyIds: [] };
      } }, gatewayConnectionBinding: { mode: "required", verification: { chainVerifier: syntheticNativeBoundary } } });
    expect((await client.chat(chat())).content).toBe("Hello E2EE");
    expect(resolutions).toBe(2); expect(t.observed.connections).toBe(2);
    expect(t.observed.gateway).toBe(1); expect(t.observed.paidTickets).toBe(1);
  });
  it("cancellation during failed initial handshake forbids a second socket", async () => {
    const abort = new AbortController();
    const t = await topology({ initialResets: 1, onInitialConnection: () => abort.abort() });
    await expect(t.client.chat(chat(abort.signal))).rejects.toThrow();
    expect(t.observed.connections).toBe(1); expect(t.observed.gateway).toBe(0);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("untrusted certificate never grants a fresh preparation", async () => {
    const t = await topology();
    const foreign = httpsServer({ key: readFileSync(join(fixture, "ca.key")), cert: readFileSync(join(fixture, "ca.pem")) });
    let attempts = 0;
    foreign.on("connection", () => attempts++); foreign.on("tlsClientError", () => {});
    await new Promise<void>(resolve => foreign.listen(0, "127.0.0.1", resolve));
    cleanup.push(() => new Promise<void>(resolve => foreign.close(() => resolve())));
    const origin = `https://127.0.0.1:${(foreign.address() as import("node:net").AddressInfo).port}`;
    const client = createClient({ ...t.clientOptions, inferenceBaseUrl: origin,
      gatewayConnectionBinding: { mode: "required", verification: { policy: policy(origin), chainVerifier: syntheticNativeBoundary } } });
    await expect(client.chat(chat())).rejects.toThrow();
    expect(attempts).toBe(1); expect(t.observed.attTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("one absolute preparation deadline prevents a fresh attempt after initial reset", async () => {
    const t = await topology({ initialResets: 1, onInitialConnection: () => {
      // The deadline starts after topology setup. Advance from the actual
      // connection callback so setup time cannot leave the budget unexpired.
      const expired = performance.now() + 180_001;
      vi.spyOn(performance, "now").mockReturnValue(expired);
    } });
    await expect(t.client.chat(chat())).rejects.toThrow();
    expect(t.observed.connections).toBe(1); expect(t.observed.gateway).toBe(0);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("DNS switches A to B after quote but provider and paid bodies stay on one A socket", async () => {
    const t = await topology({ dnsSwitch: true });
    const result = await t.client.chat(chat());
    expect(result.content).toBe("Hello E2EE");
    expect(t.observed.gateway).toBe(1);
    expect(t.observed.bytes.b).toBe(0);
    expect(t.observed.content.map(item => item.slot)).toEqual(["a", "a"]);
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.handshakes).toEqual({ a: 1, b: 0 });
    expect(t.observed.lookups).toBe(1);
  });
  it("verified B key binds provider evidence and one encrypted inference dispatch", async () => {
    const t = await topology({ start: "b" });
    const result = await t.client.chat(chat());
    expect(result.content).toBe("Hello E2EE");
    expect(t.observed.content.map(item => item.path)).toEqual(["/v1/tee/attestation", "/v1/chat/completions"]);
    expect(t.observed.content.every(item => item.slot === "b" && !item.authorization)).toBe(true);
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.controlBodies.join("")).not.toContain("synthetic-content-canary");
    expect(t.observed.content[1]!.body).not.toContain("synthetic-content-canary");
  });
  it("keeps its operation transport alive through delayed encrypted streaming", async () => {
    const t = await topology({ start: "b", streamDelayMs: 15 });
    const deltas: string[] = [];
    const result = await t.client.chat({ ...chat(), onDelta: delta => { if (delta.content) deltas.push(delta.content); } });
    expect(result.content).toBe("Hello E2EE");
    expect(deltas.join("")).toBe("Hello E2EE");
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.content).toHaveLength(2);
  });
  it("abort after a decrypted delta stops streaming without another ticket or dispatch", async () => {
    const t = await topology({ start: "b", streamDelayMs: 25 });
    const abort = new AbortController();
    let deltas = 0;
    await expect(t.client.chat({ ...chat(abort.signal), onDelta: delta => { if (delta.content) { deltas++; abort.abort(); } } })).rejects.toThrow();
    expect(deltas).toBe(1);
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.content).toHaveLength(2);
  });
  it("concurrent sessions on one client cannot replace A's pin with B's", async () => {
    const t = await topology({ switchOnEvidence: true, holdAttestationTickets: true });
    const outcomes = await Promise.allSettled([t.client.chat(chat()), t.client.chat(chat())]);
    expect(outcomes.filter(item => item.status === "fulfilled")).toHaveLength(2);
    expect(outcomes.filter(item => item.status === "rejected")).toHaveLength(0);
    expect(t.observed.paidTickets).toBe(2);
    expect(new Set(t.observed.nonces).size).toBe(2);
    expect(t.observed.content).toHaveLength(4);
  });
  it("binds image and speech bodies with separate control transports and one paid POST each", async () => {
    const t = await topology({ start: "b" });
    await t.client.images.generate({ model: "synthetic-image", prompt: "synthetic-image-canary" });
    const audio = await t.client.audio.speech.create({ model: "synthetic-speech", input: "synthetic-speech-canary" });
    expect([...audio.audio]).toEqual([1, 2, 3]);
    expect(t.observed.content.map(item => item.path)).toEqual(["/v1/images/generations", "/v1/audio/speech"]);
    expect(t.observed.content.every(item => item.slot === "b" && !item.authorization)).toBe(true);
    expect(t.observed.paidTickets).toBe(2);
    expect(t.observed.controlBodies.join("")).not.toContain("canary");
    expect(new Set(t.observed.nonces).size).toBe(2);
  });
  it("media retains A despite DNS switch and never repeats the paid ticket", async () => {
    const t = await topology({ dnsSwitch: true });
    await t.client.images.generate({ model: "synthetic-image", prompt: "synthetic-image" });
    expect(t.observed.bytes.b).toBe(0);
    expect(t.observed.content.map(item => item.slot)).toEqual(["a"]);
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.handshakes).toEqual({ a: 1, b: 0 });
    expect(t.observed.lookups).toBe(1);
  });
  it("required mode cannot be disabled by per-chat options", async () => {
    const t = await topology();
    await expect(t.client.chat({ ...chat(), requireGateway: false })).rejects.toThrow(/cannot disable/);
    expect(t.observed.gateway).toBe(0);
    expect(t.observed.attTickets).toBe(0);
  });
  it("rejects generic fetch overrides at creation", async () => {
    const t = await topology();
    expect(() => createClient({ ...t.clientOptions, fetch: async () => new Response() })).toThrow(/overrides are refused/);
    expect(t.observed.gateway).toBe(0);
  });
  it("unsupported browser runtime refuses before policy/evidence/ticket network calls", async () => {
    const t = await topology();
    vi.stubGlobal("window", { document: {} });
    await expect(t.client.chat(chat())).rejects.toThrow(/Node's native TLS/);
    expect(t.observed.gateway).toBe(0);
    expect(t.observed.attTickets).toBe(0);
    expect(t.observed.paidTickets).toBe(0);
  });
  it("expiry after provider verification refuses before minting a paid ticket", async () => {
    const t = await topology({ expireAfterProviderEvidence: true });
    await expect(t.client.chat(chat())).rejects.toThrow(/expired/);
    expect(t.observed.paidTickets).toBe(0);
    expect(t.observed.content).toHaveLength(1);
  });
  it("expiry after a paid mint refuses content dispatch and never re-mints", async () => {
    const t = await topology({ expireAfterPaidTicket: true });
    await expect(t.client.chat(chat())).rejects.toThrow();
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.content).toHaveLength(1);
    expect(t.observed.content[0]!.path).toBe("/v1/tee/attestation");
  });
  it("invalid media serialization refuses before tickets", async () => {
    const t = await topology();
    await expect(t.client.images.generate({ model: "synthetic-image", prompt: new FormData() as unknown as string })).rejects.toThrow();
    expect(t.observed.paidTickets).toBe(0);
    expect(t.observed.content).toEqual([]);
  });
  it("an unapproved compose in otherwise hardware-bound evidence refuses before tickets", async () => {
    const t = await topology({ start: "b" });
    const approved = policy(t.contentOrigin);
    approved.composeHashes = ["ff".repeat(32)];
    const client = createClient({ ...t.clientOptions, gatewayConnectionBinding: { mode: "required",
      verification: { policy: approved, chainVerifier: syntheticNativeBoundary } } });
    await expect(client.chat(chat())).rejects.toThrow(/fully verified/);
    expect(t.observed.attTickets).toBe(0);
    expect(t.observed.content).toEqual([]);
  });
  it("approval expiry after paid mint refuses even while quote evidence remains fresh", async () => {
    const t = await topology({ start: "b", expireAfterPaidTicket: true, paidExpiryAdvanceMs: 101 });
    const issuedAtMs = Date.now();
    // Explicit source fixture boundary; existing authority tests separately
    // verify signatures. This test checks provenance expiry at actual dispatch.
    const client = createClient({ ...t.clientOptions,
      gatewayPolicyUpdates: { async resolve() { return { policy: policy(t.contentOrigin), sequence: 1,
        payloadSha256: "ab".repeat(32), authority: "synthetic-source-NOT-signed", manifestSha256: "cd".repeat(32),
        issuedAtMs, expiresAtMs: issuedAtMs + 100, acceptedKeyIds: [] }; } },
      gatewayConnectionBinding: { mode: "required", verification: { chainVerifier: syntheticNativeBoundary } } });
    await expect(client.chat(chat())).rejects.toThrow();
    expect(t.observed.paidTickets).toBe(1);
    expect(t.observed.content).toHaveLength(1);
    expect(t.observed.content[0]!.path).toBe("/v1/tee/attestation");
  });
  it("without the native chain boundary an invalid synthetic quote cannot authorize content", async () => {
    const t = await topology();
    const client = createClient({ ...t.clientOptions, gatewayConnectionBinding: { mode: "required",
      verification: { policy: policy(t.contentOrigin), chainVerifier: { implementation: "synthetic-refusing-boundary", verifyChain: () => ({ verified: false }) } } } });
    await expect(client.chat(chat())).rejects.toThrow(/fully verified/);
    expect(t.observed.attTickets).toBe(0);
    expect(t.observed.content).toEqual([]);
  });
});

// Defensive helper validation; the supplied verdict is synthetic, not DCAP.
it("refuses invalid expiry bounds and noncanonical pins before constructing a transport", () => {
  const origin = "https://localhost";
  const input = { origin, policy: policy(origin), evidenceIssuedAtMs: Date.now(),
    verdict: { status: "ok", verificationLevel: "hardware-verified", tcbStatus: "UpToDate",
      binding: evidence(origin, "ab".repeat(32), "a").binding,
      checks: [{ name: "quote_signature_chain", passed: true, required: true }] } };
  const changes = [
    { approvalExpiresAtMs: NaN }, { approvalExpiresAtMs: Infinity }, { approvalExpiresAtMs: 1.5 },
    { evidenceIssuedAtMs: -1 }, { evidenceIssuedAtMs: Number.MAX_SAFE_INTEGER },
    { policy: { ...input.policy, maxEvidenceAgeMs: NaN } },
    { policy: { ...input.policy, maxEvidenceAgeMs: 0 } },
    { verdict: { ...input.verdict, binding: { ...input.verdict.binding, tls_spki_sha256: pins.a + "\n" } } }
  ];
  for (const change of changes) expect(() => createVerifiedGatewayConnection({ ...input, ...change } as Parameters<typeof createVerifiedGatewayConnection>[0])).toThrow();
});

it("retained paid image response survives drain Connection: close without replay", async () => {
  const t = await topology({ dnsSwitch: true, paidClose: true });
  const result = await t.client.images.generate({ model: "synthetic-image", prompt: "synthetic-image" });
  expect(result).toBeDefined();
  expect(t.observed.paidTickets).toBe(1);
  expect(t.observed.content.map(item => item.slot)).toEqual(["a"]);
  expect(t.observed.handshakes).toEqual({ a: 1, b: 0 });
  expect(t.observed.bytes.b).toBe(0);
});
it("retained encrypted paid stream completes through DONE with drain Connection: close", async () => {
  const t = await topology({ dnsSwitch: true, paidClose: true, streamDelayMs: 30 });
  const deltas: string[] = [];
  const result = await t.client.chat({ ...chat(), onDelta: delta => { if (delta.content) deltas.push(delta.content); } });
  expect(result.content).toBe("Hello E2EE");
  expect(deltas.join("")).toBe("Hello E2EE");
  expect(t.observed.paidTickets).toBe(1);
  expect(t.observed.content.map(item => item.slot)).toEqual(["a", "a"]);
  expect(t.observed.handshakes).toEqual({ a: 1, b: 0 });
  expect(t.observed.bytes.b).toBe(0);
});
it("signed-policy source refresh rechecks the same quote/socket and preserves provenance and immutable raw evidence", async () => {
  const t = await topology({ dnsSwitch: true });
  const issuedAtMs = Date.now();
  const forces: boolean[] = []; let prepared = 0;
  const client = createClient({ ...t.clientOptions,
    gatewayPolicyUpdates: { async resolve(_origin, _signal, force = false) {
      forces.push(force); const current = policy(t.contentOrigin);
      if (!force) current.composeHashes = ["ff".repeat(32)];
      return { policy: current, sequence: force ? 2 : 1,
        payloadSha256: (force ? "aa" : "ab").repeat(32), authority: "synthetic-source-NOT-signed",
        manifestSha256: "cd".repeat(32), issuedAtMs, expiresAtMs: issuedAtMs + 10000, acceptedKeyIds: [] };
    } }, gatewayConnectionBinding: { mode: "required", verification: { chainVerifier: {
      async prepare(quote, options) { prepared++; return syntheticNativeBoundary.prepare(quote); }
    } } } });
  const report = await client.verify({ model: MODEL, provider: "venice" });
  expect(report.trusted).toBe(true);
  expect(report.gateway.policy).toMatchObject({ origin: "signed-release-authority", sequence: 2,
    payloadSha256: "aa".repeat(32), expiresAtMs: issuedAtMs + 10000 });
  expect(forces).toEqual([false, true]); expect(prepared).toBe(1);
  expect(t.observed.gateway).toBe(1); expect(t.observed.lookups).toBe(1);
  expect(t.observed.handshakes).toEqual({ a: 1, b: 0 }); expect(t.observed.bytes.b).toBe(0);
  expect(Object.isFrozen(report.gateway.rawEvidence)).toBe(true);
  expect(Object.isFrozen(report.gateway.rawEvidence!.binding)).toBe(true);
  expect(() => { report.gateway.rawEvidence!.binding!.nonce = "00".repeat(32); }).toThrow();
  expect(t.observed.paidTickets).toBe(0);
});
it("a refreshed policy cannot weaken required transport verification before tickets", async () => {
  const t = await topology(); let refreshes = 0; const issuedAtMs = Date.now();
  const client = createClient({ ...t.clientOptions,
    gatewayPolicyUpdates: { async resolve(_origin, _signal, force = false) {
      const current = policy(t.contentOrigin);
      if (!force) current.composeHashes = ["ff".repeat(32)];
      else { refreshes++; current.requireHardwareVerified = false; }
      return { policy: current, sequence: force ? 2 : 1, payloadSha256: "ab".repeat(32),
        authority: "synthetic-source-NOT-signed", manifestSha256: "cd".repeat(32), issuedAtMs,
        expiresAtMs: issuedAtMs + 10000, acceptedKeyIds: [] };
    } }, gatewayConnectionBinding: { mode: "required", verification: { chainVerifier: syntheticNativeBoundary } } });
  await expect(client.chat(chat())).rejects.toThrow();
  expect(refreshes).toBe(1); expect(t.observed.gateway).toBe(1);
  expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0);
  expect(t.observed.content).toEqual([]);
});
it("an expired refreshed approval cannot authorize the retained socket", async () => {
  const t = await topology(); const issuedAtMs = Date.now();
  const client = createClient({ ...t.clientOptions,
    gatewayPolicyUpdates: { async resolve(_origin, _signal, force = false) {
      const current = policy(t.contentOrigin); if (!force) current.composeHashes = ["ff".repeat(32)];
      return { policy: current, sequence: force ? 2 : 1, payloadSha256: "ab".repeat(32),
        authority: "synthetic-source-NOT-signed", manifestSha256: "cd".repeat(32), issuedAtMs,
        expiresAtMs: force ? issuedAtMs - 1 : issuedAtMs + 10000, acceptedKeyIds: [] };
    } }, gatewayConnectionBinding: { mode: "required", verification: { chainVerifier: syntheticNativeBoundary } } });
  await expect(client.chat(chat())).rejects.toThrow(/expired/);
  expect(t.observed.gateway).toBe(1); expect(t.observed.attTickets).toBe(0);
  expect(t.observed.paidTickets).toBe(0); expect(t.observed.content).toEqual([]);
});

// gcp-tdx-native: synthetic registers, verity root and boot key, NOT Google
// firmware values. RTMR3 and owner registers are zero; there is no event log or
// app-compose. The node's per-boot TLS key must be the one on THIS socket.
const GCP_RELEASE = "sdk-bound-client@gcp-synthetic";
function gcpPolicy(origin: string) {
  return loadGatewayPolicy({ platformKind: "gcp-tdx-native", source: "synthetic-gcp-client-wiring-policy", version: "1",
    origins: [origin], releaseTuples: [{ tupleId: "synthetic-gcp", releaseId: GCP_RELEASE, appId: SYNTHETIC_GCP_VERITY_ROOT,
      composeHash: compose.hash, ...SYNTHETIC_GCP_REGISTERS,
      notBeforeMs: Date.now() - 60_000, expiresAtMs: Date.now() + 3_600_000 }],
    requireInTeeTls: true, requirePrivateLogs: true, requireDigestPinnedImages: true, requireHardwareVerified: true,
    requireEvidenceExpiry: true, maxEvidenceAgeMs: 300_000, acceptableTcbStatuses: ["UpToDate"] });
}
function gcpEvidence(boundSlot?: string, registers: Record<string, string> = {}) {
  return (origin: string, nonce: string, slot: string) => {
    const binding = { v: GATEWAY_BINDING_VERSION, nonce, app_id: SYNTHETIC_GCP_VERITY_ROOT, instance_id: SYNTHETIC_GCP_INSTANCE_ID,
      compose_hash: compose.hash, release_id: GCP_RELEASE, origin, key_alg: "ed25519" as const, public_key: SYNTHETIC_GCP_BOOT_KEY,
      transport: "in-tee-tls" as const, tls_spki_sha256: pins[boundSlot ?? slot]! };
    return { binding, quote: buildSyntheticGcpQuote(gatewayBindingHash(binding), registers), issued_at_ms: Date.now() };
  };
}
function gcpClient(t: Awaited<ReturnType<typeof topology>>, pilot = true) {
  return createClient({ ...t.clientOptions, gatewayConnectionBinding: { mode: "required", verification: {
    policy: gcpPolicy(t.contentOrigin), chainVerifier: syntheticNativeBoundary, ...(pilot ? { unqualifiedPlatformPilot: true } : {}) } } });
}

describe("gcp-tdx-native mandatory real-connection key binding — synthetic native port, real TLS", () => {
  it("public verifyGateway uses the configured native retained binding without ticket calls", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const result = await gcpClient(t).verifyGateway({ signal: AbortSignal.timeout(5000) });
    expect(result.verdict.status).toBe("ok");
    expect(result.verdict.verificationLevel).toBe("hardware-verified");
    expect(result.verdict.binding?.tls_spki_sha256).toBe(pins.a);
    expect(t.observed.handshakes).toEqual({ a: 1, b: 0 });
    expect(t.observed.connections).toBe(1); expect(t.observed.gateway).toBe(1);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0);
    expect(t.observed.content).toHaveLength(0);
  });
  it("public verifyGateway rejects per-call replacements before any connection", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const client = gcpClient(t);
    for (const input of [{ nonce: "ab".repeat(32) }, { policy: gcpPolicy(t.contentOrigin) },
      { chainVerifier: syntheticNativeBoundary }, { unqualifiedPlatformPilot: true },
      { observedTlsSpkiSha256: pins.a }, { allowCandidatePolicy: true }]) {
      await expect(client.verifyGateway(input)).rejects.toMatchObject({ code: "unsupported_request" });
    }
    expect(t.observed.connections).toBe(0); expect(t.observed.gateway).toBe(0);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0);
    expect(t.observed.content).toHaveLength(0);
  });
  it("public verifyGateway refuses a quote for another TLS key", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence("b");
    await expect(gcpClient(t).verifyGateway()).rejects.toMatchObject({ code: "attestation_untrusted" });
    expect(t.observed.connections).toBe(1); expect(t.observed.gateway).toBe(1);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("pilot: the per-boot key on the retained socket matches the quote, and content uses that socket", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    expect((await gcpClient(t).chat(chat())).content).toBe("Hello E2EE");
    expect(t.observed.handshakes).toEqual({ a: 1, b: 0 }); expect(t.observed.gateway).toBe(1);
    expect(t.observed.content.map(c => c.slot)).toEqual(["a", "a"]);
  });
  it("wrong key: a quote binding another node's TLS key yields zero tickets and zero content", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence("b");
    await expect(gcpClient(t).chat(chat())).rejects.toMatchObject({ code: "attestation_untrusted" });
    expect(t.observed.gateway).toBe(1);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("wrong platform tuple: an unapproved firmware register yields zero tickets and zero content", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence(undefined, { mrTd: "5e".repeat(48) });
    await expect(gcpClient(t).chat(chat())).rejects.toMatchObject({ code: "attestation_untrusted" });
    expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("qualified platform: works without a pilot opt-in", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    expect((await gcpClient(t, false).chat(chat())).content).toBe("Hello E2EE");
    expect(t.observed.connections).toBe(1); expect(t.observed.gateway).toBe(1);
    expect(t.observed.content.map(c => c.slot)).toEqual(["a", "a"]);
  });
});

// verifyContentNode: the owner-signed release policy v3 feed (synthetic owner
// keys, mocked https feed) plus one retained real-TLS attestation. Read-only:
// no ticket, no content, one socket.
const { verifyContentNode }: typeof import("../dist/gateway/content-node.js") = await import(
  packageRoot ? pathToFileURL(join(packageRoot, "dist/gateway/content-node.js")).href : new URL("../dist/gateway/content-node.js", import.meta.url).href);
const v3: typeof import("../dist/gateway/release-v3.js") = await import(
  packageRoot ? pathToFileURL(join(packageRoot, "dist/gateway/release-v3.js")).href : new URL("../dist/gateway/release-v3.js", import.meta.url).href);
const { ed25519 } = await import("@noble/curves/ed25519.js");
const V3_SEEDS = [new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22)];
const V3_KEYS = [
  { keyId: "custodian.prod.usb" as const, publicKey: Buffer.from(ed25519.getPublicKey(V3_SEEDS[0]!)).toString("hex") },
  { keyId: "custodian.prod.laptop" as const, publicKey: Buffer.from(ed25519.getPublicKey(V3_SEEDS[1]!)).toString("hex") }
];
const V3_TRUST = { deploymentId: "gcp-content-qualification", groupId: "release-owner-qualification", keys: V3_KEYS,
  ownerRootSha256: v3.releaseOwnerRootSha256({ deploymentId: "gcp-content-qualification", groupId: "release-owner-qualification", keys: V3_KEYS }),
  minimumPolicySequence: 1 };
const V3_FEED = "https://policy.example/.well-known/anonrouter-content-release-v3.json";
const V3_TUPLE = { tupleId: "synthetic-gcp", mrTd: SYNTHETIC_GCP_REGISTERS.mrTd, mrConfigId: "00".repeat(48), mrOwner: "00".repeat(48),
  mrOwnerConfig: "00".repeat(48), rtmr0: SYNTHETIC_GCP_REGISTERS.rtmr0, rtmr1: SYNTHETIC_GCP_REGISTERS.rtmr1,
  rtmr2: SYNTHETIC_GCP_REGISTERS.rtmr2, rtmr3: "00".repeat(48), tdAttributes: SYNTHETIC_GCP_REGISTERS.tdAttributes,
  xfam: SYNTHETIC_GCP_REGISTERS.xfam };
function v3Envelope(extra: Record<string, unknown> = {}) {
  const payload = { protocol: "anonrouter-content-node-bootstrap-v1", kind: "content-node-release-policy",
    deploymentId: "gcp-content-qualification", sequence: 1, issuedAtMs: Date.now(), tuples: [V3_TUPLE], revokedTuples: [],
    revokedGenerations: [], minimumGenerationRevision: 1, maxEvidenceAgeMs: 300000, tcbStatus: "UpToDate", ...extra };
  const message = v3.releaseEnvelopeV3Message("release-policy", V3_TRUST.groupId, V3_TRUST.ownerRootSha256, payload);
  return { protocol: "anonrouter-content-release-envelope-v3", role: "release-policy", groupId: V3_TRUST.groupId,
    ownerRootSha256: V3_TRUST.ownerRootSha256, payload,
    signatures: V3_SEEDS.map((seed, index) => ({ keyId: V3_KEYS[index]!.keyId, signature: Buffer.from(ed25519.sign(message, seed)).toString("hex") })) };
}
function v3Source(origin: string, envelope: unknown) {
  const feed = vi.fn(async () => new Response(JSON.stringify(envelope), { status: 200, headers: { "content-type": "application/json" } }));
  const states: Array<{ sequence: number; payloadSha256: string }> = [];
  const source = v3.createReleasePolicyV3Source({ trust: V3_TRUST, url: V3_FEED, origins: [origin], fetch: feed as unknown as typeof fetch,
    stateStore: { async observe(_authority, checkpoint) { states.push(checkpoint); } } });
  return { source, feed, states };
}

describe("verifyContentNode — signed release-v3 feed, synthetic native port, real TLS", () => {
  it("verifies on one retained socket with no ticket or content", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const { source, feed, states } = v3Source(t.contentOrigin, v3Envelope());
    const result = await verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary,
      signal: AbortSignal.timeout(5000) });
    expect(result.verdict.status).toBe("ok");
    expect(result.verdict.verificationLevel).toBe("hardware-verified");
    expect(result.verdict.instanceIdentity).toBe("not-applicable");
    expect(result.policy).toMatchObject({ origin: "signed-release-policy-v3", sequence: 1, ownerRootSha256: V3_TRUST.ownerRootSha256 });
    expect(result.rawEvidence?.binding).toBeTruthy();
    expect(feed).toHaveBeenCalledTimes(1); expect(states).toHaveLength(1);
    expect(t.observed.connections).toBe(1); expect(t.observed.gateway).toBe(1);
    expect(t.observed.attTickets).toBe(0); expect(t.observed.paidTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("returns a failed verdict for a quote binding another node's TLS key", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence("b");
    const { source } = v3Source(t.contentOrigin, v3Envelope());
    const result = await verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary });
    expect(result.verdict.status).toBe("failed");
    expect(result.verdict.checks.filter(c => c.required && !c.passed).map(c => c.name)).toEqual(["tls_certificate_bound_to_quote"]);
    expect(result.rawEvidence).toBeNull();
    expect(t.observed.attTickets).toBe(0); expect(t.observed.content).toHaveLength(0);
  });
  it("returns a failed verdict for a revoked tuple", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const other = { ...V3_TUPLE, tupleId: "other", mrTd: "5e".repeat(48) };
    const { source } = v3Source(t.contentOrigin, v3Envelope({ tuples: [other], revokedTuples: [v3.releaseTupleDigest(V3_TUPLE)] }));
    const result = await verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary });
    expect(result.verdict.status).toBe("failed");
    expect(result.verdict.checks.filter(c => c.required && !c.passed).map(c => c.name))
      .toEqual(["release_tuple_not_revoked", "release_tuple_matched"]);
  });
  it("requires the PZID when the signed policy says so, even on an approved image", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const { source } = v3Source(t.contentOrigin, v3Envelope({ requireGcePzid: true }));
    const result = await verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary });
    expect(result.verdict.status).toBe("failed");
    expect(result.verdict.checks.filter(c => c.required && !c.passed).map(c => c.name)).toEqual(["gce_instance_identity"]);
  });
  it("accepts a signed tcbGrace and still verifies UpToDate", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const now = Date.now();
    const { source } = v3Source(t.contentOrigin, v3Envelope({ issuedAtMs: now,
      tcbGrace: { statuses: ["OutOfDate"], advisoryIds: ["INTEL-SA-01367"], notAfterMs: now + 86_400_000 } }));
    const result = await verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary });
    expect(result.verdict.status).toBe("ok"); expect(result.verdict.tcbStatus).toBe("UpToDate");
  });
  it("refuses a tampered owner signature before any connection", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const envelope = v3Envelope(); envelope.signatures[1]!.signature = "00".repeat(64);
    const { source } = v3Source(t.contentOrigin, envelope);
    await expect(verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary }))
      .rejects.toMatchObject({ code: "signature_invalid" });
    expect(t.observed.connections).toBe(0); expect(t.observed.gateway).toBe(0);
  });
  it("refuses an origin the policy source does not authorize before any connection", async () => {
    const t = await topology(); evidenceOverride = gcpEvidence();
    const { source } = v3Source("https://content.other.example", v3Envelope());
    await expect(verifyContentNode({ origin: t.contentOrigin, policySource: source, chainVerifier: syntheticNativeBoundary }))
      .rejects.toMatchObject({ code: "unauthorized_origin" });
    expect(t.observed.connections).toBe(0);
  });
});
