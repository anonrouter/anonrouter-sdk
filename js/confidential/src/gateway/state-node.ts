// Optional Node adapter. Imported dynamically; browser imports stay safe.
import { mkdir, open, readFile, rename, rmdir, unlink, lstat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { GatewayPolicyError } from "./policy.js";
import { checkGatewayPolicyCheckpoint } from "./state.js";
import type { GatewayPolicyStateStore } from "./authority.js";

export function createFileGatewayPolicyStateStore(directory = join(homedir(), ".cache", "anonrouter", "gateway-policy-v1")): GatewayPolicyStateStore {
  return { async observe(authority, checkpoint) {
    checkpoint = { sequence: checkpoint.sequence, payloadSha256: checkpoint.payloadSha256 };
    checkGatewayPolicyCheckpoint(checkpoint, checkpoint);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new GatewayPolicyError("unsafe gateway policy state directory");
    const path = join(directory, createHash("sha256").update(authority).digest("hex") + ".json");
    const lock = path + ".lock";
    const deadline = Date.now() + 10_000;
    for (;;) {
      try { await mkdir(lock, { mode: 0o700 }); break; }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST" || Date.now() >= deadline) throw new GatewayPolicyError("gateway policy state locked/unavailable");
        await new Promise(r => setTimeout(r, 25));
      }
    }
    try {
      let previous: unknown;
      try { previous = JSON.parse(await readFile(path, "utf8")); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new GatewayPolicyError("invalid gateway policy state file"); }
      if (previous !== undefined) {
        checkGatewayPolicyCheckpoint(previous, checkpoint);
        if ((previous as { sequence: number }).sequence === checkpoint.sequence) return;
      }
      const temp = path + "." + randomBytes(12).toString("hex") + ".tmp";
      const file = await open(temp, "wx", 0o600);
      try {
        await file.writeFile(JSON.stringify(checkpoint) + "\n", "utf8"); await file.sync();
      } finally { await file.close(); }
      try {
        await rename(temp, path);
        const dir = await open(directory, "r");
        try { await dir.sync(); } finally { await dir.close(); }
      } finally { await unlink(temp).catch(() => {}); }
    } finally { await rmdir(lock); }
  } };
}
