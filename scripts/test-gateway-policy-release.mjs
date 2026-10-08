#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { prepareGatewayPolicyRelease, assembleGatewayPolicyRelease } from './gateway-policy-release.mjs';
const policy=JSON.parse(readFileSync(new URL('../shared/gateway-policies.json',import.meta.url),'utf8')).policies[0].policy;
const manifest={schema:'anonrouter.release-manifest/v2',status:'live-hardware-measurement',source:{dirty:false},deployment:{transport:'in-tee-tls',app_id:policy.appIds[0],origin:policy.origins[0],os_image_hash:policy.platform.osImageHash[0]},compose:{measured_hash:policy.composeHashes[0]},release_id:policy.releaseIds[0]};
const bytes=Buffer.from(JSON.stringify(manifest));
const bound={...policy,source:'anonrouter-release-manifest-sha256:'+createHash('sha256').update(bytes).digest('hex')};
const now=Date.now();
const p=prepareGatewayPolicyRelease(bytes,bound,1,now,now+60000);
assert.equal(JSON.parse(p.payload).sequence,1);
assert.ok(p.signingBytes.startsWith('anonrouter.gateway-policy-signature/v1\n'));
assert.throws(()=>prepareGatewayPolicyRelease(bytes,policy,1,now,now+60000));
assert.throws(()=>prepareGatewayPolicyRelease(bytes,{...bound,composeHashes:['00'.repeat(32)]},1,now,now+60000));
assert.throws(()=>prepareGatewayPolicyRelease(bytes,{...bound,requireHardwareVerified:false},1,now,now+60000));
assert.throws(()=>prepareGatewayPolicyRelease(bytes,bound,1,now,now+604800001));
assert.throws(()=>assembleGatewayPolicyRelease(p.payload,[],now));
const vectors=JSON.parse(readFileSync(new URL('../shared/vectors/gateway-policy-authority.json',import.meta.url),'utf8'));
assert.throws(()=>assembleGatewayPolicyRelease(vectors.cases[0].envelope.payload,vectors.cases[0].envelope.signatures,vectors.nowMs));

// ---- phala-dstack-kms overlap tuples ------------------------------------------
// Synthetic manifests and keys; the root below is a TEST roster, never production.
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { verifySignedGatewayPolicy } from '../js/confidential/dist/gateway/authority.js';
import { prepareTupleGatewayPolicyRelease, gatewayManifestSet } from './gateway-policy-release.mjs';
const sha256=b=>createHash('sha256').update(b).digest('hex');
const ORIGIN='https://api.anonrouter.ai';
function manifestFor(release,appId,compose,osImage,origin=ORIGIN){return Buffer.from(JSON.stringify({schema:'anonrouter.release-manifest/v2',status:'live-hardware-measurement',release_id:release,source:{dirty:false},deployment:{app_id:appId,origin,transport:'in-tee-tls',os_image_hash:osImage},compose:{measured_hash:sha256(compose)},app_compose:compose}));}
const kms=Buffer.from(JSON.stringify({name:'kms',id:'aa'.repeat(33)})).toString('hex');
const releases=[['content@old','11'.repeat(20),'{"name":"old"}','bd'.repeat(32)],['content@new','11'.repeat(20),'{"name":"new"}','be'.repeat(32)]];
const manifests=releases.map(r=>manifestFor(...r));
const tupleFor=([release,appId,compose,osImage],i)=>({tupleId:`${release}@large`,releaseId:release,appId,composeHash:sha256(compose),
  mrTd:'f0'.repeat(48),mrConfigId:'01'+sha256(compose)+'00'.repeat(15),rtmr0:'a0'.repeat(48),rtmr1:(i?'b2':'b1').repeat(48),rtmr2:'c0'.repeat(48),
  osImageHash:osImage,keyProviderPayload:kms,notBeforeMs:now-1000,expiresAtMs:now+30*86400000});
const set=gatewayManifestSet(manifests);
const tuplePolicy={platformKind:'phala-dstack-kms',source:`anonrouter-release-manifest-sha256:${set.sha256}`,version:'overlap-1',origins:[ORIGIN,'https://api.private.anonrouter.ai'],
  releaseTuples:releases.map(tupleFor),requireInTeeTls:true,requirePrivateLogs:true,requireDigestPinnedImages:true,requireHardwareVerified:true,
  acceptableTcbStatuses:['UpToDate'],requireEvidenceExpiry:true,maxEvidenceAgeMs:300000};
const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
const rawPublic=k=>Buffer.from(k.publicKey.export({format:'jwk'}).x,'base64url').toString('hex');
const testRoot={...packagedGatewayPolicyAuthorityForTest(),keys:{'test-0':rawPublic(keys[0]),'test-1':rawPublic(keys[1])}};
function packagedGatewayPolicyAuthorityForTest(){return JSON.parse(readFileSync(new URL('../shared/gateway-policy-authority.json',import.meta.url),'utf8'));}
const prepared=prepareTupleGatewayPolicyRelease(manifests,tuplePolicy,1,now,now+86400000,testRoot);
assert.equal(prepared.review.tuples.length,2);
assert.deepEqual(prepared.review.tuples.map(t=>Object.keys(t.unboundReviewRequired)),[['mrTd','rtmr0','rtmr1','rtmr2','keyProviderPayload'],['mrTd','rtmr0','rtmr1','rtmr2','keyProviderPayload']]);
assert.equal(prepared.review.payloadSha256,sha256(prepared.payload));
assert.equal(JSON.parse(prepared.payload).manifestSha256,set.sha256);
const envelope={schema:'anonrouter.gateway-policy-envelope/v1',payload:prepared.payload,
  signatures:keys.map((k,i)=>({keyId:`test-${i}`,signature:edSign(null,Buffer.from(prepared.signingBytes),k.privateKey).toString('hex')}))};
for(const origin of testRoot.origins){const v=verifySignedGatewayPolicy(envelope,testRoot,origin,now+1);assert.equal(v.policy.releaseTuples.length,2);}
// Same bytes, Python verifier, when an interpreter with the package is available.
if(process.env.ANONROUTER_PYTHON){
  const out=execFileSync(process.env.ANONROUTER_PYTHON,['-c','import json,sys\nfrom anonrouter_confidential.gateway.authority import verify_signed_gateway_policy\nd=json.loads(sys.stdin.read())\nprint(len(verify_signed_gateway_policy(d["e"],d["r"],d["o"],d["n"])["policy"].release_tuples))'],
    {input:JSON.stringify({e:envelope,r:testRoot,o:ORIGIN,n:now+1}),encoding:'utf8',env:{...process.env,PYTHONPATH:new URL('../python/src',import.meta.url).pathname}});
  assert.equal(out.trim(),'2');
}
const refuse=(why,...args)=>assert.throws(()=>prepareTupleGatewayPolicyRelease(...args),why);
const withTuple=(i,change)=>({...tuplePolicy,releaseTuples:tuplePolicy.releaseTuples.map((t,j)=>j===i?{...t,...change}:t)});
refuse(/disagrees with its retained manifest: composeHash/,manifests,withTuple(1,{composeHash:'00'.repeat(32)}),1,now,now+1000,testRoot);
refuse(/mrConfigId/,manifests,withTuple(0,{mrConfigId:'02'+tuplePolicy.releaseTuples[0].mrConfigId.slice(2)}),1,now,now+1000,testRoot);
refuse(/osImageHash/,manifests,withTuple(0,{osImageHash:'00'.repeat(32)}),1,now,now+1000,testRoot);
refuse(/not backed by exactly one/,[manifests[0]],{...tuplePolicy,source:`anonrouter-release-manifest-sha256:${gatewayManifestSet([manifests[0]]).sha256}`},1,now,now+1000,testRoot);
const withUnused=[...manifests,manifestFor('content@unused','11'.repeat(20),'{"name":"x"}','bf'.repeat(32))];
refuse(/every retained manifest must back/,withUnused,{...tuplePolicy,source:`anonrouter-release-manifest-sha256:${gatewayManifestSet(withUnused).sha256}`,
  releaseTuples:[...tuplePolicy.releaseTuples,{...tuplePolicy.releaseTuples[0],tupleId:'spare'}]},1,now,now+1000,testRoot);
refuse(/canonical manifest set/,manifests,{...tuplePolicy,source:'anonrouter-release-manifest-sha256:'+'00'.repeat(32)},1,now,now+1000,testRoot);
refuse(/already expired/,manifests,withTuple(0,{notBeforeMs:now-3000,expiresAtMs:now-1}),1,now,now+1000,testRoot);
refuse(/invalid sequence or validity/,manifests,tuplePolicy,1,now,now+604800001,testRoot);
const tampered=JSON.parse(manifests[0]);tampered.app_compose+=' ';
refuse(/does not hash to its measured compose/,[Buffer.from(JSON.stringify(tampered)),manifests[1]],tuplePolicy,1,now,now+1000,testRoot);
const foreign=[manifestFor(...releases[0],'https://other.example'),manifests[1]];
refuse(/origin is not authorized/,foreign,{...tuplePolicy,source:`anonrouter-release-manifest-sha256:${gatewayManifestSet(foreign).sha256}`},1,now,now+1000,testRoot);
// The legacy single-manifest path refuses tuple documents rather than half-checking them.
assert.throws(()=>prepareGatewayPolicyRelease(manifests[0],tuplePolicy,1,now,now+60000),/prepareTupleGatewayPolicyRelease/);
process.stdout.write('Gateway policy release tooling: legacy preparation and refusals, plus phala overlap tuples (2-of-2 signed, JS'+(process.env.ANONROUTER_PYTHON?'+Python':'')+' verified) and ten tuple refusals passed.\n');
