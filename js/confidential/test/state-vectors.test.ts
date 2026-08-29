// The stable verdict contract, checked against the SHARED vectors the Python
// package also loads. A divergence here is not cosmetic: if one language ranked
// the states differently, a caller who wrote the same threshold in both would get
// different security decisions from identical evidence.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { atLeast, isTrusted, stateForLevel, TRUSTED_STATES } from "../src/verify/state.js";
import type { RouteVerificationState } from "../src/verify/state.js";

const vectors = JSON.parse(readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../shared/vectors/verification-states.json"),
  "utf8"
)) as {
  states: RouteVerificationState[];
  trustedStates: RouteVerificationState[];
  levelMapping: Array<{ level: string; state: RouteVerificationState }>;
  atLeast: Array<{ state: RouteVerificationState; required: RouteVerificationState; expected: boolean }>;
};

describe("shared verification-state vectors", () => {
  it("maps every pinned level to the pinned state", () => {
    for (const v of vectors.levelMapping) {
      expect(stateForLevel(v.level), `level ${v.level || "(empty)"}`).toBe(v.state);
    }
  });

  it("agrees on the full atLeast matrix", () => {
    // Exhaustive: 5 states x 5 thresholds, so a new state cannot be added in one
    // language without this failing in both.
    expect(vectors.atLeast).toHaveLength(vectors.states.length * vectors.states.length);
    for (const v of vectors.atLeast) {
      expect(atLeast(v.state, v.required), `atLeast(${v.state}, ${v.required})`).toBe(v.expected);
    }
  });

  it("agrees on exactly which states are trusted", () => {
    for (const state of vectors.states) {
      expect(isTrusted(state), state).toBe(vectors.trustedStates.includes(state));
    }
    expect([...TRUSTED_STATES].sort()).toEqual([...vectors.trustedStates].sort());
  });
});
