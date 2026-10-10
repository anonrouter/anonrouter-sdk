import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import fixture from '../../../shared/vectors/dcap-same-fmspc-pck-chains.json' with { type: 'json' };
import { CollateralCache, type AcquiredCollateral } from '../src/gateway/dcap/collateral.js';
import { createAnonRouterDcapVerifier } from '../src/gateway/dcap/engine.js';
// Synthetic extraction carriers, not valid acceptance quotes; only public PCKs.
const carriers = fixture.chains.map(c => {
  expect(createHash('sha256').update(c.pem).digest('hex')).toBe(c.sha256);
  return Buffer.from(`extraction-only\0${c.pem}\0`, 'latin1').toString('hex');
});
const cached: AcquiredCollateral = { fmspc: fixture.fmspc, fetchedAtMs: 1, nextUpdateMs: 1000,
  collateral: { pck_crl_issuer_chain: 'issuer', root_ca_crl: '00', pck_crl: '01',
    tcb_info_issuer_chain: 'tcb issuer', tcb_info: 'exact signed bytes', tcb_info_signature: '02',
    qe_identity_issuer_chain: 'qe issuer', qe_identity: 'exact qe bytes', qe_identity_signature: '03',
    pck_certificate_chain: fixture.chains[0].pem } };
describe('per-quote PCK binding', () => {
  it('reuses one platform fetch for distinct PCKs without mutating previous inputs', async () => {
    let fetches = 0; const cache = new CollateralCache(async () => { fetches++; return cached; });
    const a = await cache.get(carriers[0], 10), b = await cache.get(carriers[1], 10);
    expect(fetches).toBe(1);
    expect(a.collateral.pck_certificate_chain).toBe(fixture.chains[0].pem);
    expect(b.collateral.pck_certificate_chain).toBe(fixture.chains[1].pem);
    expect(cached.collateral.pck_certificate_chain).toBe(fixture.chains[0].pem);
    expect(a.collateral).not.toBe(b.collateral);
    const { pck_certificate_chain: _, ...platform } = cached.collateral;
    expect(cache.peek(fixture.fmspc)?.collateral).toEqual(platform);
    expect((await cache.get(carriers[0], 10)).collateral).toEqual(a.collateral);
  });
  it('refuses cached collateral for a different platform before insertion', async () => {
    const cache = new CollateralCache(async () => ({ ...cached, fmspc: '20a06f000000' }));
    await expect(cache.get(carriers[1], 10)).rejects.toThrow('platform');
    expect(cache.peek('20a06f000000')).toBeUndefined();
  });
  it('native adapter omits other-host PCK overrides and preserves signed inputs for both quotes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ar-pck-wire-'));
    try {
      const binary = join(dir, 'capture.mjs'), captured = join(dir, 'request.json');
      writeFileSync(binary, `#!${process.execPath}\nimport fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(captured)},fs.readFileSync(0));\nconsole.log(JSON.stringify({v:1,verified:false,advisory_ids:[],error:'synthetic carrier; no acceptance',engine:'wire-capture'}));\n`);
      chmodSync(binary, 0o755);
      const factory = createAnonRouterDcapVerifier({ binaryPath: binary, collateral: cached.collateral, fetchCollateral: false });
      for (const quote of carriers) {
        const verifier = await factory.prepare(quote, { nowMs: 10 });
        expect((await verifier.verifyChain(quote)).verified).toBe(false);
        const wire = JSON.parse(readFileSync(captured, 'utf8'));
        expect(wire.quote).toBe(quote);
        const { pck_certificate_chain: _, ...platform } = cached.collateral;
        expect(wire.collateral).toEqual(platform);
      }
      expect(cached.collateral.pck_certificate_chain).toBe(fixture.chains[0].pem);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
