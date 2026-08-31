// The anonrouter-verify command's contract.
//
// Every case here has a Python twin loading the SAME shared/vectors/cli-contract.json.
// Two commands with the same name that disagreed about their exit codes or their
// JSON shape would be worse than having only one, because a script written against
// either would silently mean something different under the other.

import { describe, expect, it } from "vitest";
import contract from "../../../shared/vectors/cli-contract.json" with { type: "json" };
import { EXIT_MET, EXIT_NOT_MET, EXIT_USAGE, parseArgs, runCli, SCHEMA, UsageError, type CliIo } from "../src/cli/run.js";

/** Capture what one invocation printed. */
function capture(): CliIo & { stdout: string; stderr: string } {
  const sink = {
    stdout: "",
    stderr: "",
    out(text: string) { sink.stdout += text; },
    err(text: string) { sink.stderr += text; }
  };
  return sink;
}

describe("exit codes and schema", () => {
  it("matches the shared contract", () => {
    expect(SCHEMA).toBe(contract.schema);
    expect(EXIT_MET).toBe(contract.exitCodes.met);
    expect(EXIT_NOT_MET).toBe(contract.exitCodes.notMet);
    expect(EXIT_USAGE).toBe(contract.exitCodes.usage);
  });

  it("keeps 'not met' and 'wrong command' distinct", () => {
    // Load-bearing. If a mistyped command exited 1, a CI job gating on the exit
    // code would read its own typo as a verification answer.
    expect(EXIT_NOT_MET).not.toBe(EXIT_USAGE);
  });
});

describe("inputs that must be refused before anything is contacted", () => {
  for (const testCase of contract.usageCases) {
    it(testCase.name, async () => {
      const io = capture();
      const code = await runCli(testCase.argv, io);
      expect(code).toBe(testCase.exitCode);
      expect(io.stderr).toContain(testCase.stderrContains);
      // Nothing was established, so nothing may be printed as though it was.
      expect(io.stdout).toBe("");
    });
  }

  it("refuses an API key on argv even though accepting it would be easy", async () => {
    // argv is visible in the process table and lands in shell history. Silently
    // ignoring the flag would leave the key exposed AND the command unauthorized.
    const io = capture();
    const code = await runCli(["route", "--origin", "https://x.example", "--provider", "venice", "--model", "m", "--api-key", "ar_live_secret"], io);
    expect(code).toBe(EXIT_USAGE);
    expect(io.stderr).not.toContain("ar_live_secret");
  });
});

describe("parsed options", () => {
  it("defaults to the contract's assurance level", () => {
    expect(parseArgs(["gateway", "--origin", "https://x.example"]).require).toBe(contract.defaultRequire);
  });

  it("--dcap-binary implies --dcap, so naming an engine is enough to use it", () => {
    const options = parseArgs(["gateway", "--origin", "https://x.example", "--dcap-binary", "/opt/engine"]);
    expect(options.dcap).toBe(true);
    expect(options.dcapBinary).toBe("/opt/engine");
  });

  it("accepts every command the contract names", () => {
    for (const command of contract.commands) {
      const argv = command === "doctor"
        ? [command]
        : command === "route"
          ? [command, "--origin", "https://x.example", "--provider", "venice", "--model", "m"]
          : [command, "--origin", "https://x.example"];
      expect(parseArgs(argv).command).toBe(command);
    }
  });

  it("throws UsageError rather than exiting, so the runner decides the code", () => {
    expect(() => parseArgs(["nope"])).toThrow(UsageError);
  });
});

describe("doctor", () => {
  it("prints exactly the contract's document keys", async () => {
    const io = capture();
    const code = await runCli(["doctor", "--compact"], io);
    expect(code).toBe(EXIT_MET);
    const document = JSON.parse(io.stdout);
    expect(Object.keys(document)).toEqual(contract.documentKeys.doctor);
    expect(Object.keys(document.engine)).toEqual(expect.arrayContaining(contract.engineKeys));
    expect(Object.keys(document.pin)).toEqual(contract.pinKeys);
  });

  it("reports the shipped candidate pin as needing an explicit opt-in", async () => {
    const io = capture();
    await runCli(["doctor", "--origin", "https://api.private.anonrouter.ai", "--compact"], io);
    const document = JSON.parse(io.stdout);
    expect(document.pin.present).toBe(true);
    expect(document.pin.status).toBe("candidate");
    expect(document.pin.requiresOptIn).toBe(true);
  });

  it("reports no pin for an origin this package does not cover", async () => {
    const io = capture();
    await runCli(["doctor", "--origin", "https://example.invalid", "--compact"], io);
    const document = JSON.parse(io.stdout);
    expect(document.pin.present).toBe(false);
  });

  it("does not gate: a missing engine is information, not a failure", async () => {
    // doctor answering "you cannot reach hardware_verified here" is a successful
    // report. Exiting nonzero would make `doctor` unusable in a setup script.
    const io = capture();
    const code = await runCli(["doctor", "--compact"], io);
    expect(code).toBe(EXIT_MET);
  });
});

describe("an origin with no pin fails closed offline", () => {
  const offline = contract.offlineCase;

  it(offline.name, async () => {
    // No network call is possible here: the policy is resolved first, and with
    // nothing pinned there is nothing to check evidence against, so fetching it
    // would only be reading the server's own claim back to the caller.
    const io = capture();
    const code = await runCli(offline.argv, io);
    expect(code).toBe(offline.exitCode);
    const document = JSON.parse(io.stdout);
    expect(document.outcome.met).toBe(offline.outcome.met);
    expect(document.outcome.state).toBe(offline.outcome.state);
    expect(document.gateway.state).toBe(offline.gatewayState);
    expect(document.provider.requested).toBe(offline.providerRequested);
    expect(String(document.outcome.reason)).toContain(offline.reasonContains);
  });

  it("prints exactly the contract's document keys", async () => {
    const io = capture();
    await runCli(offline.argv, io);
    const document = JSON.parse(io.stdout);
    expect(Object.keys(document)).toEqual(contract.documentKeys.verify);
    expect(Object.keys(document.requested)).toEqual(contract.requestedKeys);
    expect(Object.keys(document.outcome)).toEqual(contract.outcomeKeys);
    expect(Object.keys(document.gateway)).toEqual(expect.arrayContaining(contract.hopKeys));
    expect(Object.keys(document.provider)).toEqual(expect.arrayContaining(contract.hopKeys));
  });

  it("never prints evidence bodies or anything credential-shaped", async () => {
    const io = capture();
    await runCli(offline.argv, io);
    for (const forbidden of contract.neverPrinted) {
      expect(io.stdout).not.toContain(forbidden);
    }
  });
});

describe("--compact is the only thing that changes the bytes", () => {
  it("emits one line when compact and indented JSON otherwise", async () => {
    const compact = capture();
    await runCli(["doctor", "--compact"], compact);
    expect(compact.stdout.trimEnd().includes("\n")).toBe(false);

    const pretty = capture();
    await runCli(["doctor"], pretty);
    expect(pretty.stdout.includes("\n  ")).toBe(true);
    // Same document either way: formatting must not be a semantic difference.
    expect(JSON.parse(pretty.stdout)).toEqual(JSON.parse(compact.stdout));
  });
});
