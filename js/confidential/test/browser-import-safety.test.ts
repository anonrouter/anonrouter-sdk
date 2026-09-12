// Importing `@anonrouter/confidential` must not drag in a Node builtin.
//
// The default entry is advertised as browser-safe, and several modules behind it
// deliberately reach Node APIs through non-literal dynamic specifiers so a
// bundler never has to resolve them: the Chutes certificate check, the DCAP
// adapter behind its own export path, and now the Tinfoil pinned-TLS
// observation. That pattern is one careless `import { createHash } from
// "node:crypto"` away from breaking, and the breakage shows up as a bundler
// error in someone else's app rather than as a failing test here.
//
// So this walks the STATIC import graph from the entry point and refuses any
// `node:` specifier in it. Dynamic `await import(specifier)` calls are invisible
// to this scan by construction, which is exactly the distinction being enforced.

import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");

/** `import ... from "x"`, `export ... from "x"`, and bare `import "x"`. */
const SPECIFIER = /(?:^|\n)\s*(?:import|export)(?:[\s\S]*?)from\s*["']([^"']+)["']|(?:^|\n)\s*import\s*["']([^"']+)["']/g;

function staticImportGraph(entry: string): { visited: Set<string>; nodeBuiltins: string[] } {
  const visited = new Set<string>();
  const nodeBuiltins: string[] = [];

  const walk = (file: string): void => {
    if (visited.has(file)) return;
    visited.add(file);
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(SPECIFIER)) {
      const specifier = match[1] ?? match[2];
      if (specifier.startsWith("node:")) {
        nodeBuiltins.push(`${relative(SRC, file)} imports ${specifier}`);
        continue;
      }
      if (!specifier.startsWith(".")) continue;
      // Emitted ESM specifiers carry .js; the source next to them is .ts.
      const resolved = resolve(dirname(file), specifier).replace(/\.js$/, ".ts");
      if (existsSync(resolved)) walk(resolved);
    }
  };

  walk(entry);
  return { visited, nodeBuiltins };
}

describe("the default entry point stays importable in a browser", () => {
  it("reaches no Node builtin through a static import", () => {
    const { visited, nodeBuiltins } = staticImportGraph(resolve(SRC, "index.ts"));
    // Guard the guard: a graph that walked almost nothing would pass vacuously.
    expect(visited.size).toBeGreaterThan(20);
    expect(nodeBuiltins).toEqual([]);
  });

  it("keeps the Tinfoil TLS observation behind dynamic specifiers", () => {
    // It is the newest member of this pattern and the easiest to regress: the
    // obvious way to write it is a plain `import { request } from "node:https"`.
    const source = readFileSync(resolve(SRC, "tinfoil-tls.ts"), "utf8");
    expect(source).not.toMatch(/from\s*["']node:/);
    for (const builtin of ["node:https", "node:tls", "node:crypto"]) {
      expect(source, `${builtin} should be reached dynamically`).toContain(`"${builtin}"`);
    }
  });
});
