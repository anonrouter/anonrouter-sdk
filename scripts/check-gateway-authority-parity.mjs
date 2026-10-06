#!/usr/bin/env node
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifySignedGatewayPolicy } from '../js/confidential/dist/gateway/authority.js';
import { createFileGatewayPolicyStateStore } from '../js/confidential/dist/gateway/state-node.js';
const root = resolve(import.meta.dirname, '..');
const file = join(root, 'shared/vectors/gateway-policy-authority.json');
const v = JSON.parse(readFileSync(file, 'utf8'));
const results = v.cases.map(c => {try { verifySignedGatewayPolicy(c.envelope,v.root,v.origin,v.nowMs);return true;} catch {return false;} });
const python = process.env.ANONROUTER_PYTHON || 'python3';
const code = `import json,sys\nfrom anonrouter_confidential.gateway.authority import verify_signed_gateway_policy\nv=json.load(open(sys.argv[1]));out=[]\nfor c in v['cases']:\n try: verify_signed_gateway_policy(c['envelope'],v['root'],v['origin'],v['nowMs']);out.append(True)\n except Exception: out.append(False)\nprint(json.dumps(out))`;
const output=execFileSync(python,['-c',code,file],{encoding:'utf8',env:{...process.env,PYTHONPATH:join(root,'python/src')}});
if(JSON.stringify(results)!==JSON.stringify(JSON.parse(output)) || results.some((r,i)=>r!==v.cases[i].accepted))throw new Error('gateway approval acceptance drift');
const directory=mkdtempSync(join(tmpdir(),'anonrouter-policy-parity-'));
try {
 const store=createFileGatewayPolicyStateStore(directory);
 const approval=verifySignedGatewayPolicy(v.cases[1].envelope,v.root,v.origin,v.nowMs);
 await store.observe(v.root.authority,{sequence:approval.sequence,payloadSha256:approval.payloadSha256});
 const storageCode=`import sys\nfrom anonrouter_confidential.gateway.state import FileGatewayPolicyStateStore\nfrom anonrouter_confidential.gateway.policy import GatewayPolicyError\ns=FileGatewayPolicyStateStore(sys.argv[1])\ntry: s(sys.argv[2],{'sequence':1,'payloadSha256':'00'*32})\nexcept GatewayPolicyError: pass\nelse: raise RuntimeError('Python accepted Node rollback')\ns(sys.argv[2],{'sequence':3,'payloadSha256':'11'*32})`;
 execFileSync(python,['-c',storageCode,directory,v.root.authority],{env:{...process.env,PYTHONPATH:join(root,'python/src')}});
 let refused=false;try {await store.observe(v.root.authority,{sequence:2,payloadSha256:approval.payloadSha256});}catch {refused=true;}
 if(!refused)throw new Error('Node accepted Python rollback');
} finally {rmSync(directory,{recursive:true,force:true});}
process.stdout.write(`Gateway authority parity: ${results.length} signed vectors and both cross-language durable rollback refusals passed.\n`);
