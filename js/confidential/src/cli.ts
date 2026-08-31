#!/usr/bin/env node
// The `anonrouter-verify` entry point.
//
// Deliberately thin: everything the command does lives in ./cli/run.ts, which
// takes its argv and its output sinks as arguments and returns an exit code. That
// split is what lets the test suite exercise the whole command, including the
// exact JSON it prints, without spawning a process, and it is why the JS and
// Python documents can be compared field for field.

import { runCli, EXIT_USAGE } from "./cli/run.js";

runCli(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (error) => {
    // An unexpected throw is a broken command, not a failed verification, so it
    // exits with the usage code rather than the "did not verify" code. Confusing
    // the two would let a crash read as a security answer.
    process.stderr.write(`anonrouter-verify: ${error instanceof Error ? error.message : "unexpected failure"}\n`);
    process.exitCode = EXIT_USAGE;
  }
);
