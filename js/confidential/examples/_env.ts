// Loads a local .env (git-ignored) sitting next to the package, so you can set
// ANONROUTER_API_KEY once instead of retyping it. Minimal and dependency-free:
// it never overrides a variable you set explicitly on the command line.
//
// Create js/confidential/.env with:  ANONROUTER_API_KEY=ar_...

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const envPath = fileURLToPath(new URL("../.env", import.meta.url));
if (existsSync(envPath)) {
  for (const raw of readFileSync(envPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    // Explicit command-line env wins over the file.
    if (process.env[match[1]] === undefined) process.env[match[1]] = value;
  }
}
