import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFileGatewayPolicyStateStore } from '../src/gateway/state-node.js';
import { describe, expect, it, vi } from 'vitest';
import { createClient } from '../src/client.js';
import * as gatewayVerify from '../src/gateway/verify.js';
import { createSignedGatewayPolicySource, verifySignedGatewayPolicy, packagedGatewayPolicyAuthority, type GatewayPolicyAuthority } from '../src/gateway/authority.js';
import { loadGatewayPolicy } from '../src/gateway/policy.js';
const vectors = JSON.parse(readFileSync(new URL('../../../shared/vectors/gateway-policy-authority.json', import.meta.url), 'utf8'));
const root = vectors.root as GatewayPolicyAuthority;
const valid = vectors.cases[0].envelope;
const next = vectors.cases[1].envelope;
const origin = vectors.origin;
function source(fetcher: typeof fetch, now: () => number = () => vectors.nowMs, extra = {}) {
  return createSignedGatewayPolicySource({ authority: root, fetch: fetcher, now, stateStore: { observe: async () => {} }, ...extra });
}
describe('signed gateway approval contract', () => {
  for (const c of vectors.cases) it(c.name, () => {
    const run = () => verifySignedGatewayPolicy(c.envelope, root, origin, vectors.nowMs);
    if (c.accepted) expect(run().policy.requireHardwareVerified).toBe(true);
    else expect(run).toThrow();
  });
  it('stages production roots without turning on an unpublished feed', () => {
    expect(packagedGatewayPolicyAuthority().enabled).toBe(false);
    expect(packagedGatewayPolicyAuthority().threshold).toBe(2);
  });
  it('rejects earlier approvals and a changed payload reusing a sequence', () => {
    const approved = verifySignedGatewayPolicy(next, root, origin, vectors.nowMs);
    expect(() => verifySignedGatewayPolicy(valid, root, origin, vectors.nowMs, approved)).toThrow(/rollback/);
    expect(() => verifySignedGatewayPolicy(next, root, origin, vectors.nowMs, { sequence: 2, payloadSha256: '00'.repeat(32) })).toThrow(/conflicting/);
  });
  it('rejects a gateway used as its own approval source', () => {
    expect(() => verifySignedGatewayPolicy(valid, {...root, url: origin+'/policy'}, origin, vectors.nowMs)).toThrow(/separate/);
  });
  it('cannot count one physical key under two IDs', () => {
    const keys = {...root.keys}; keys['test-1'] = keys['test-0']!;
    expect(() => verifySignedGatewayPolicy(valid, {...root, keys}, origin, vectors.nowMs)).toThrow(/distinct/);
  });
  it('rejects unsupported origins', () => {
    expect(() => verifySignedGatewayPolicy(valid, root, 'https://unknown.invalid', vectors.nowMs)).toThrow(/origin/);
  });
});
describe('automatic refresh and client wiring', () => {
  it('adopts future signed measurements without upgrading the SDK', async () => {
    let time = vectors.nowMs; let answer = valid; let calls = 0;
    const s = source(async (_, init) => {
      calls++; expect(init?.credentials).toBe('omit'); expect(init?.redirect).toBe('error');
      expect(new Headers(init?.headers).has('authorization')).toBe(false);
      return Response.json(answer);
    }, () => time);
    expect((await s.resolve(origin)).sequence).toBe(1);
    time += root.refreshMs; answer = next;
    expect((await s.resolve(origin)).policy.version).toBe('next-release');
    expect(calls).toBe(2);
  });
  it('rechecks signed expiry with a cached approval', async () => {
    let time = vectors.nowMs;
    const s = source(async()=>Response.json(valid),()=>time);
    await s.resolve(origin); time += 10001;
    await expect(s.resolve(origin)).rejects.toThrow(/expired/);
  });
  it('uses an unexpired verified cache only for transport outages', async () => {
    let time = vectors.nowMs; let answer: unknown = valid;
    const s = source(async()=> answer ? Response.json(answer) : new Response(null,{status:503}),()=>time);
    await s.resolve(origin); answer = null; time += root.refreshMs;
    expect((await s.resolve(origin)).sequence).toBe(1);
    time += root.refreshMs; answer = vectors.cases.find((c: any)=>c.name==='bad-signature').envelope;
    await expect(s.resolve(origin)).rejects.toThrow(/signature/);
  });
  it('does not fall back to shipped pins on a missing publication', async () => {
    const s = source(async()=>new Response(null,{status:404}));
    const client = createClient({apiKey:'local-test-key', baseUrl:origin, gatewayPolicyUpdates:s, fetch:async()=>{throw new Error('must not fetch gateway');}});
    await expect(client.verifyGateway()).rejects.toThrow(/publication unavailable/);
  });
  it('waits for durable rollback state before returning an approval', async () => {
    const s = source(async()=>Response.json(valid),()=>vectors.nowMs,{stateStore:{observe:async()=>{throw new Error('persisted newer approval');}}});
    await expect(s.resolve(origin)).rejects.toThrow(/persisted newer/);
  });
  it('restores a checkpoint across resolver restarts', async () => {
    const checkpoint = verifySignedGatewayPolicy(next,root,origin,vectors.nowMs);
    const s = source(async()=>Response.json(valid),()=>vectors.nowMs,{checkpoint});
    await expect(s.resolve(origin)).rejects.toThrow(/rollback/);
  });
  it('checks expiry after a slow fetch', async () => {
    let time = vectors.nowMs;
    const s = source(async()=>{time+=10001;return Response.json(valid);},()=>time);
    await expect(s.resolve(origin)).rejects.toThrow(/expired/);
  });
  it('rejects oversized and redirected documents', async () => {
    await expect(source(async()=>new Response(' '.repeat(262145))).resolve(origin)).rejects.toThrow(/too large/);
    await expect(source(async()=>new Response(null,{status:302})).resolve(origin)).rejects.toThrow(/unavailable/);
  });
  it('honors an explicit exact policy without consulting the feed', async () => {
    const client = createClient({apiKey:'local-test-key',baseUrl:origin,gatewayPolicyUpdates:{resolve:async()=>{throw new Error('feed must not be consulted');}},fetch:async()=>Response.json({binding:{},quote:'bad'})});
    const result=await client.verifyGateway({policy:loadGatewayPolicy(JSON.parse(valid.payload).policy)});
    expect(result.policy.origin).toBe('caller-supplied');
    expect(result.verdict.status).toBe('failed');
  });
  it('reports provenance without upgrading bad hardware evidence', async () => {
    const client=createClient({apiKey:'local-test-key',baseUrl:origin,gatewayPolicyUpdates:source(async()=>Response.json(next)),fetch:async()=>Response.json({binding:{},quote:'bad'})});
    const clock = vi.spyOn(Date, 'now').mockReturnValue(vectors.nowMs);
    let result;
    try { result=await client.verifyGateway(); } finally { clock.mockRestore(); }
    expect(result.policy.origin).toBe('signed-release-authority');
    expect(result.policy.sequence).toBe(2);
    expect(result.verdict.status).toBe('failed');
  });
});

it('persists the high-water mark across independent Node stores', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'anonrouter-policy-test-'));
  try {
    const first = createFileGatewayPolicyStateStore(directory);
    const second = createFileGatewayPolicyStateStore(directory);
    const approved = verifySignedGatewayPolicy(next, root, origin, vectors.nowMs);
    await first.observe(root.authority, approved);
    await expect(second.observe(root.authority, verifySignedGatewayPolicy(valid, root, origin, vectors.nowMs))).rejects.toThrow(/persisted/);
    await second.observe(root.authority, approved);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

it('refreshes after frequent cached reads without sliding the freshness window', async () => {
  let time = vectors.nowMs; let calls = 0;
  const s = source(async()=>{calls++;return Response.json(valid);},()=>time);
  await s.resolve(origin); time += 400; await s.resolve(origin); time += 400; await s.resolve(origin);
  expect(calls).toBe(1); time += 300; await s.resolve(origin); expect(calls).toBe(2);
});
it('forces a refresh on demand before the normal interval', async () => {
  let answer = valid; let calls = 0;
  const s = source(async()=>{calls++;return Response.json(answer);});
  await s.resolve(origin); answer = next;
  expect((await s.resolve(origin, undefined, true)).sequence).toBe(2); expect(calls).toBe(2);
});
it('refuses a stale cache even if its signed expiry is still valid', async () => {
  let time = vectors.nowMs; let available = true;
  const s = createSignedGatewayPolicySource({authority:{...root,maxStaleMs:1000},now:()=>time,
    stateStore:{observe:async()=>{}},fetch:async()=>available?Response.json(valid):new Response(null,{status:503})});
  await s.resolve(origin); available=false; time+=1001;
  await expect(s.resolve(origin)).rejects.toThrow(/stale/);
});
it('refreshes once after hardware-verified identity drift and never widens the policy', async () => {
  const old = verifySignedGatewayPolicy(valid,root,origin,vectors.nowMs);
  const updated = verifySignedGatewayPolicy(next,root,origin,vectors.nowMs);
  const refreshes: (boolean|undefined)[] = [];
  const drift = {status:'failed' as const,verificationLevel:'unverified' as const,reason:'compose_hash_pinned',
    binding:null,appCompose:null,measurements:null,tcbStatus:null,policySource:'test',policyVersion:'test',verifiedAtMs:vectors.nowMs,checks:[
    {name:'quote_signature_chain',passed:true,required:true}, {name:'compose_hash_pinned',passed:false,required:true}
  ]};
  const verifier = vi.spyOn(gatewayVerify,'verifyGatewayAttestation').mockReturnValue(drift);
  const clock = vi.spyOn(Date,'now').mockReturnValue(vectors.nowMs);
  try {
    const client = createClient({apiKey:'local-test',baseUrl:origin,fetch:async()=>Response.json({binding:{},quote:'bad'}),
      gatewayPolicyUpdates:{resolve:async(_,__,force)=>{refreshes.push(force);return force?updated:old;}}});
    const result = await client.verifyGateway();
    expect(refreshes).toEqual([false,true]);
    expect(verifier).toHaveBeenCalledTimes(2);
    expect(result.policy.sequence).toBe(2);
    expect(result.verdict.status).toBe('failed');
    expect(verifier.mock.calls[1]![1].policy.composeHashes).toEqual(updated.policy.composeHashes);
  } finally {verifier.mockRestore();clock.mockRestore();}
});
