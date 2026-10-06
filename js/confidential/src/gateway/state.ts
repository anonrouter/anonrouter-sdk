import type { GatewayPolicyCheckpoint, GatewayPolicyStateStore } from "./authority.js";
import { GatewayPolicyError } from "./policy.js";
export function checkGatewayPolicyCheckpoint(previous: unknown, next: GatewayPolicyCheckpoint): void {
  if (!previous || typeof previous !== "object") throw new GatewayPolicyError("invalid stored gateway policy checkpoint");
  const p = previous as GatewayPolicyCheckpoint;
  if (typeof p.payloadSha256 !== "string" || !Number.isSafeInteger(p.sequence) || p.sequence < 1 || !/^[0-9a-f]{64}$/.test(p.payloadSha256)) throw new GatewayPolicyError("invalid stored gateway policy checkpoint");
  if (next.sequence < p.sequence || (next.sequence === p.sequence && next.payloadSha256 !== p.payloadSha256)) throw new GatewayPolicyError("gateway policy rollback or conflicting persisted sequence");
}
/** IndexedDB read/check/write is a single transaction across browser tabs. */
export function createBrowserGatewayPolicyStateStore(): GatewayPolicyStateStore {
  let database: Promise<IDBDatabase> | undefined;
  return { async observe(authority, checkpoint) {
    checkpoint = { sequence: checkpoint.sequence, payloadSha256: checkpoint.payloadSha256 };
    checkGatewayPolicyCheckpoint(checkpoint, checkpoint);
    database ??= new Promise((resolve, reject) => {
      const request = indexedDB.open("anonrouter-gateway-policy-v1", 1);
      request.onupgradeneeded = () => { request.result.createObjectStore("checkpoints"); };
      request.onerror = () => reject(new GatewayPolicyError("gateway policy state unavailable"));
      request.onblocked = () => reject(new GatewayPolicyError("gateway policy state blocked"));
      request.onsuccess = () => resolve(request.result);
    });
    const db = await database;
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction("checkpoints", "readwrite", { durability: "strict" });
      const store = transaction.objectStore("checkpoints");
      const request = store.get(authority);
      let failure: unknown;
      request.onsuccess = () => {
        try { if (request.result !== undefined) checkGatewayPolicyCheckpoint(request.result, checkpoint);
          store.put(checkpoint, authority); }
        catch (error) { failure = error; transaction.abort(); }
      };
      transaction.oncomplete = () => resolve();
      transaction.onabort = transaction.onerror = () => reject(failure ?? new GatewayPolicyError("gateway policy state unavailable"));
    });
  } };
}
export function createDefaultGatewayPolicyStateStore(): GatewayPolicyStateStore {
  if (typeof process !== "undefined" && process.versions?.node) {
    let store: Promise<GatewayPolicyStateStore> | undefined;
    return { async observe(authority, checkpoint) {
      const nodeModule = "./state-node.js";
      store ??= import(nodeModule).then(m => m.createFileGatewayPolicyStateStore());
      await (await store).observe(authority, checkpoint);
    } };
  }
  if (typeof indexedDB !== "undefined") return createBrowserGatewayPolicyStateStore();
  return { async observe() { throw new GatewayPolicyError("durable gateway policy state is unavailable; supply a stateStore"); } };
}
