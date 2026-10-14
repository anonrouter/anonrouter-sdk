// Synthetic child/fetch lifecycle, plus two real single-process Node lifecycle
// fixtures. No native engine, Intel requests or hardware/capacity acceptance.
import { EventEmitter } from "node:events";
import { execFile, type ChildProcess } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import vectors from "../../../shared/vectors/dcap.json" with { type: "json" };
import { buildDcapEngineRequest, createAnonRouterDcapVerifier, runDcapEngine } from "../src/gateway/dcap/engine.js";
import { CollateralCache, fetchIntelCollateral, type AcquiredCollateral } from "../src/gateway/dcap/collateral.js";

vi.mock("node:child_process", async importOriginal => ({ ...await importOriginal<typeof import("node:child_process")>(), execFile: vi.fn() }));
const quote = vectors.quoteParsing.fixtures.quoteWithPckChain;
const collateral = vectors.engineWire.collateral;
const payload = buildDcapEngineRequest(quote, collateral, 1);
const pass = '{"verified":true,"tcb_status":"UpToDate","engine":"synthetic-NOT-native"}';
const fresh = (): AcquiredCollateral => ({ collateral: { ...collateral, pck_certificate_chain: vectors.quoteParsing.fixtures.pckChain }, fmspc: vectors.quoteParsing.fixtures.leafFmspc, nextUpdateMs: Date.now() + 60_000, fetchedAtMs: Date.now() });
const tick = async () => { await Promise.resolve(); await Promise.resolve(); };
class Child extends EventEmitter {
  stdin = Object.assign(new EventEmitter(), { end: vi.fn() });
  kill = vi.fn(() => true);
}

describe("Node DCAP cancellation and join (synthetic fixtures)", () => {
  let child: Child, callback: (error: any, stdout: string) => void, controller: AbortController;
  let directory: string, binary: string;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "ar-dcap-cancel-")); binary = join(directory, "synthetic-engine");
    writeFileSync(binary, "synthetic-not-executed"); chmodSync(binary, 0o700);
    child = new Child(); controller = new AbortController();
    vi.mocked(execFile).mockReset();
    vi.mocked(execFile).mockImplementation(((...args: any[]) => {
      callback = args[3]; return child;
    }) as unknown as typeof execFile);
  });
  afterEach(() => { vi.useRealTimers(); rmSync(directory, { recursive: true, force: true }); });

  it("pre-abort refuses both engine and factory before process or collateral fetch", async () => {
    controller.abort(); const fetcher = vi.fn(async () => fresh());
    expect((await runDcapEngine(binary, payload, 100, controller.signal)).verified).toBe(false);
    const verifier = await createAnonRouterDcapVerifier({ binaryPath: binary, collateralCache: new CollateralCache(fetcher) })
      .prepare(quote, { signal: controller.signal });
    expect(verifier.verifyChain(quote).verified).toBe(false); expect(execFile).not.toHaveBeenCalled(); expect(fetcher).not.toHaveBeenCalled();
  });

  it("cancel kills but does not settle at callback/exit; late valid stdout is refused after close", async () => {
    let finished = false; const job = runDcapEngine(binary, payload, 1000, controller.signal).then(value => { finished = true; return value; });
    expect(child.stdin.end).toHaveBeenCalledWith(JSON.stringify(payload)); controller.abort();
    expect(child.kill).toHaveBeenCalledWith("SIGKILL"); callback(null, pass); child.emit("exit", 0); await tick(); expect(finished).toBe(false);
    child.emit("close", 0); const result = await job; expect(result.verified).toBe(false); expect(result.error).toContain("cancelled");
  });

  it("close alone cannot settle until bounded callback is joined", async () => {
    let finished = false; const job = runDcapEngine(binary, payload, 1000, controller.signal).then(value => { finished = true; return value; });
    controller.abort(); child.emit("close", null, "SIGKILL"); await tick(); expect(finished).toBe(false);
    callback(null, pass); expect((await job).verified).toBe(false);
  });

  it("timeout kills and joins, and cannot accept earlier valid stdout", async () => {
    vi.useFakeTimers(); let finished = false;
    const job = runDcapEngine(binary, payload, 100, controller.signal).then(value => { finished = true; return value; });
    callback(null, pass); await vi.advanceTimersByTimeAsync(100); expect(child.kill).toHaveBeenCalledWith("SIGKILL"); expect(finished).toBe(false);
    child.emit("close", null, "SIGKILL"); const result = await job; expect(result.verified).toBe(false); expect(result.error).toContain("timeout");
  });

  it("kill failure retains the join wait and errors contain no child secrets", async () => {
    child.kill.mockImplementation(() => { throw new Error("synthetic PRIVATE secret"); });
    let finished = false; const job = runDcapEngine(binary, payload, 1000, controller.signal).then(value => { finished = true; return value; });
    controller.abort(); callback(Object.assign(new Error("synthetic PRIVATE secret"), { code: "PRIVATE_SECRET" }), pass);
    await tick(); expect(finished).toBe(false); child.emit("close", 1);
    const result = await job; expect(result.verified).toBe(false); expect(JSON.stringify(result)).not.toContain("PRIVATE");
  });

  it("failed spawn error and stdin error do not skip close", async () => {
    let finished = false; const job = runDcapEngine(binary, payload, 1000).then(value => { finished = true; return value; });
    child.emit("error", new Error("synthetic PRIVATE secret")); callback(new Error("synthetic PRIVATE secret"), "");
    await tick(); expect(finished).toBe(false); child.emit("close", -2); expect((await job).verified).toBe(false);
    child = new Child(); const second = runDcapEngine(binary, payload, 1000); child.stdin.emit("error", new Error("PRIVATE"));
    expect(child.kill).toHaveBeenCalledWith("SIGKILL"); callback(null, pass); child.emit("close", 1); expect((await second).verified).toBe(false);
  });

  it("preserves exact executable/empty argv/stdin bounds and normal nonzero not-verified verdict", async () => {
    const job = runDcapEngine(binary, payload, 1000);
    expect(execFile).toHaveBeenCalledWith(binary, [], { maxBuffer: 262144, encoding: "utf8", killSignal: "SIGKILL" }, expect.any(Function));
    callback(Object.assign(new Error("exit"), { code: 1 }), '{"verified":false,"tcb_status":"OutOfDate","error":"unaccepted TCB"}');
    child.emit("close", 1); expect((await job).tcbStatus).toBe("OutOfDate");
  });

  it("output overflow or killed child cannot accept valid partial stdout", async () => {
    const job = runDcapEngine(binary, payload, 1000);
    callback(Object.assign(new Error("PRIVATE"), { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }), pass); child.emit("close", 1);
    expect((await job).verified).toBe(false);
  });

  it("factory cancels native verification and refuses a late success", async () => {
    const job = createAnonRouterDcapVerifier({ binaryPath: binary, collateral }).prepare(quote, { signal: controller.signal });
    controller.abort(); callback(null, pass); child.emit("close", 0);
    const verifier = await job; expect(verifier.verifyChain(quote).verified).toBe(false);
  });

  it("factory refuses custom cache failure without publishing its exception", async () => {
    const cache = new CollateralCache(async () => { throw new Error("synthetic PRIVATE secret"); });
    const verifier = await createAnonRouterDcapVerifier({ binaryPath: binary, collateralCache: cache }).prepare(quote);
    const result = verifier.verifyChain(quote);
    expect(result.verified).toBe(false); expect(JSON.stringify(result)).not.toContain("PRIVATE");
    expect(execFile).not.toHaveBeenCalled();
  });

  it("cancelled cache borrow cannot store late collateral or cancel an unrelated borrower", async () => {
    const pending: Array<{ signal?: AbortSignal; resolve: (value: AcquiredCollateral) => void }> = [];
    const cache = new CollateralCache((_quote, signal) => new Promise(resolve => pending.push({ signal, resolve })));
    const first = cache.get(quote, Date.now(), controller.signal); const refused = expect(first).rejects.toThrow("cancelled");
    const other = new AbortController(); const second = cache.get(quote, Date.now(), other.signal);
    controller.abort(); expect(pending[0]!.signal!.aborted).toBe(true); expect(pending[1]!.signal!.aborted).toBe(false);
    const value = fresh(); pending[0]!.resolve(value); await refused; expect(cache.peek(value.fmspc)).toBeUndefined();
    pending[1]!.resolve(value); expect(await second).toEqual(value); const { pck_certificate_chain: _chain, ...platform } = value.collateral;
    expect(cache.peek(value.fmspc)).toEqual({ ...value, collateral: platform });
    const aborted = new AbortController(); aborted.abort(); await expect(cache.get(quote, 1, aborted.signal)).rejects.toThrow("cancelled");
  });

  it("pre-aborted collateral acquisition sends no requests", async () => {
    controller.abort(); const fetcher = vi.fn();
    await expect(fetchIntelCollateral(quote, { signal: controller.signal, fetch: fetcher })).rejects.toThrow("cancelled");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("collateral abort reaches all four requests and joins their rejection before returning", async () => {
    const pending: Array<{ signal: AbortSignal; reject: (error: unknown) => void }> = [];
    const fetcher = vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => pending.push({ signal: init!.signal!, reject })));
    let finished = false; const job = fetchIntelCollateral(quote, { signal: controller.signal, fetch: fetcher }).finally(() => { finished = true; });
    const rejected = expect(job).rejects.toThrow("cancelled"); expect(pending).toHaveLength(4); controller.abort();
    expect(pending.every(request => request.signal.aborted)).toBe(true);
    pending[0]!.reject(new Error("synthetic PRIVATE secret")); await tick(); expect(finished).toBe(false);
    for (const request of pending.slice(1)) request.reject(new Error("synthetic PRIVATE secret")); await rejected;
  });

  it("a failed collateral request aborts and joins sibling requests", async () => {
    const pending: Array<{ signal: AbortSignal; reject: (error: unknown) => void }> = [];
    const fetcher = vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => pending.push({ signal: init!.signal!, reject })));
    const job = fetchIntelCollateral(quote, { fetch: fetcher }); const rejected = expect(job).rejects.toThrow("could not reach");
    pending[0]!.reject(new Error("synthetic PRIVATE secret")); await tick(); await tick();
    expect(pending.every(request => request.signal.aborted)).toBe(true);
    for (const request of pending.slice(1)) request.reject(new Error("synthetic PRIVATE secret")); await rejected;
  });

  it("factory late cancelled collateral never spawns verification", async () => {
    let release!: (value: AcquiredCollateral) => void;
    const cache = new CollateralCache((_quote, signal) => { expect(signal).toBe(controller.signal); return new Promise(resolve => { release = resolve; }); });
    const job = createAnonRouterDcapVerifier({ binaryPath: binary, collateralCache: cache }).prepare(quote, { signal: controller.signal });
    controller.abort(); release(fresh()); const verifier = await job;
    expect(verifier.verifyChain(quote).verified).toBe(false); expect(execFile).not.toHaveBeenCalled();
  });

  it("cancel during response-body reads joins all bodies and refuses late bytes", async () => {
    const bodies: Array<{ finish: () => void }> = [];
    const fetcher = vi.fn(async (url: string) => {
      const text = url.includes("/tcb?") ? '{"tcbInfo":{"nextUpdate":"2099-01-01T00:00:00Z"},"signature":"aa"}'
        : '{"enclaveIdentity":{},"signature":"aa"}';
      return { ok: true, headers: new Headers({ "TCB-Info-Issuer-Chain": "synthetic", "SGX-Enclave-Identity-Issuer-Chain": "synthetic", "SGX-PCK-CRL-Issuer-Chain": "synthetic" }),
        text: () => new Promise<string>(resolve => bodies.push({ finish: () => resolve(text) })),
        arrayBuffer: () => new Promise<ArrayBuffer>(resolve => bodies.push({ finish: () => resolve(new ArrayBuffer(1)) })) } as Response;
    });
    let finished = false; const job = fetchIntelCollateral(quote, { signal: controller.signal, fetch: fetcher }).finally(() => { finished = true; });
    const rejected = expect(job).rejects.toThrow("cancelled"); await tick(); expect(bodies).toHaveLength(4);
    controller.abort(); bodies[0]!.finish(); await tick(); expect(finished).toBe(false);
    for (const body of bodies.slice(1)) body.finish(); await rejected;
  });

  it("successful acquisition preserves exact signed document bytes and bounded cache expiry", async () => {
    const tcb = '{"nextUpdate":"2099-01-01T00:00:00Z", "synthetic":1}', qe = '{"synthetic":2}';
    const fetcher = vi.fn(async (url: string) => new Response(url.includes("/tcb?") ? `{"tcbInfo":${tcb},"signature":"aa"}`
      : url.includes("/qe/identity") ? `{"enclaveIdentity":${qe},"signature":"bb"}` : new Uint8Array([1, 2]),
    { headers: { "TCB-Info-Issuer-Chain": "synthetic", "SGX-Enclave-Identity-Issuer-Chain": "synthetic", "SGX-PCK-CRL-Issuer-Chain": "synthetic" } }));
    const result = await fetchIntelCollateral(quote, { fetch: fetcher });
    expect(fetcher).toHaveBeenCalledTimes(4); expect(result.collateral.tcb_info).toBe(tcb); expect(result.collateral.qe_identity).toBe(qe);
    expect(result.nextUpdateMs).toBe(Date.parse("2099-01-01T00:00:00Z"));
    expect(fetcher.mock.calls.every(([url]) => url.startsWith("https://"))).toBe(true);
  });

  // POSIX executable shebang fixtures; Windows process acceptance is separate.
  // These fixtures deliberately launch no children. They exercise real SDK
  // execFile kill/join, not the native engine's audited no-child or hardware path.
  for (const mode of ["cancel", "deadline"] as const) it.skipIf(process.platform === "win32")(
    `real single-process ${mode} joins close and death and refuses already-printed success`, async () => {
      const actual = await vi.importActual<typeof import("node:child_process")>("node:child_process");
      let realChild: ChildProcess | undefined, stdoutSeen = false, closed = false, stdoutBytes = 0;
      vi.mocked(execFile).mockImplementation(((...args: any[]) => {
        const spawned = (actual.execFile as unknown as (...parameters: any[]) => ChildProcess)(...args);
        realChild = spawned;
        spawned.stdout!.on("data", (chunk: Buffer) => {
          stdoutBytes += chunk.length; stdoutSeen ||= chunk.toString("utf8").includes("synthetic-NOT-native");
        });
        spawned.once("close", () => { closed = true; });
        return spawned;
      }) as unknown as typeof execFile);
      writeFileSync(binary, `#!${process.execPath}\nprocess.stdin.resume();process.stdin.on("end",()=>{process.stdout.write(${JSON.stringify(pass + "\n")});setInterval(()=>{},1000);});\n`);
      chmodSync(binary, 0o700);
      let settled = false;
      const started = performance.now();
      // Starting a real executable can take over a second on a busy host. Give
      // the fixture time to print its verdict before exercising cancellation or
      // deadline expiry; these are test allowances, not SDK production budgets.
      const job = runDcapEngine(binary, payload, mode === "cancel" ? 8000 : 6500, controller.signal)
        .then(value => { settled = true; return value; });
      try {
        while (!stdoutSeen && !closed && performance.now() - started < 5000) await new Promise(resolve => setTimeout(resolve, 5));
        expect(stdoutSeen).toBe(true); expect(stdoutBytes).toBeLessThan(1024); expect(settled).toBe(false);
        expect(realChild?.pid).toBeGreaterThan(1); process.kill(realChild!.pid!, 0);
        if (mode === "cancel") controller.abort();
        const verdict = await job;
        expect(verdict.verified).toBe(false); expect(closed).toBe(true);
        let dead = false;
        try { process.kill(realChild!.pid!, 0); } catch (error) { dead = (error as NodeJS.ErrnoException).code === "ESRCH"; }
        expect(dead).toBe(true);
      } finally {
        // Never remove the private executable fixture while it is still alive.
        controller.abort();
        if (realChild && !closed) {
          realChild.kill("SIGKILL"); await new Promise(resolve => realChild!.once("close", resolve));
        }
        await job;
      }
    }, 10000);
});
