"""Real local TLS and SDK crypto. Native Intel verification is an explicit
synthetic quote-boundary fixture; this is not hardware/release acceptance."""
from __future__ import annotations
import asyncio
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python/tests'))
if os.environ.get('SDK_BOUND_INSTALLED') != '1':
    sys.path.insert(0, str(ROOT / 'python/src'))
else:
    import anonrouter_confidential as installed_sdk
    if not Path(installed_sdk.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError('Installed-artifact mode requires the isolated environment package')
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from gateway_fixtures import build_app_compose, build_synthetic_event_log, build_synthetic_gcp_quote, build_synthetic_tdx_quote, build_vm_config, SYNTHETIC_GCP_BOOT_KEY, SYNTHETIC_GCP_INSTANCE_ID, SYNTHETIC_GCP_REGISTERS, SYNTHETIC_GCP_VERITY_ROOT, SYNTHETIC_MR_CONFIG_ID, SYNTHETIC_OS_IMAGE_HASH
from test_route_binding_negatives import venice_evidence
from anonrouter_confidential.client import create_client
from anonrouter_confidential.crypto import venice
from anonrouter_confidential.gateway.binding import gateway_binding_hash
from anonrouter_confidential.gateway.policy import load_gateway_policy
from anonrouter_confidential.gateway.authority import SignedGatewayPolicySource
from anonrouter_confidential.gateway.transport_sync import SpkiBoundGatewayTransport, BoundGatewayTransportError

APP='0123456789abcdef0123456789abcdef01234567'
INSTANCE='fedcba9876543210fedcba9876543210fedcba98'
KMS='fe'*32
RELEASE='sdk-bound-python@synthetic'
MODEL='venice-uncensored'
MANIFEST,COMPOSE=build_app_compose()
LOG=build_synthetic_event_log(app_id=APP,instance_id=INSTANCE,compose_hash=COMPOSE,key_provider_id=KMS)
ENCLAVE_PRIV='9911AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556677'

class NativeBoundary:
    def prepare(self, quote, **kwargs):
        class Prepared:
            implementation='synthetic-NOT-Intel'
            def verify_chain(self, candidate, collateral=None):
                return candidate == quote, 'UpToDate'
        return Prepared()

class LocalServer:
    def __init__(self, handler, fixture=None, initial='a', host='127.0.0.1', port=0, initial_resets=0, on_initial_connection=None):
        self.handler,self.fixture,self.active=handler,fixture,initial
        self.contexts={}
        self.pins={}
        if fixture:
            for name in ['a','b']:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(fixture/f'{name}.pem',fixture/f'{name}.key')
                self.contexts[name]=context
                cert=x509.load_pem_x509_certificate((fixture/f'{name}.pem').read_bytes())
                self.pins[name]=hashlib.sha256(cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.socket=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET);
        if ':' in host:self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        self.socket.bind((host,port));self.socket.listen();self.socket.settimeout(.05)
        self.origin=f'{"https" if fixture else "http"}://127.0.0.1:{self.socket.getsockname()[1]}'
        self.stop=threading.Event();self.sockets=set();self.threads=[];self.lock=threading.Lock();self.bytes={'a':0,'b':0};self.handshakes={'a':0,'b':0};self.errors=[]
        self.initial_resets=initial_resets;self.on_initial_connection=on_initial_connection;self.connections=0
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()
    def accept(self):
        while not self.stop.is_set():
            try:raw,_=self.socket.accept()
            except (TimeoutError,OSError):continue
            slot=self.active
            with self.lock:self.sockets.add(raw);self.connections+=1;reset=self.connections<=self.initial_resets
            worker=threading.Thread(target=self.serve,args=(raw,slot,reset),daemon=True);self.threads.append(worker);worker.start()
    def serve(self, raw, slot, reset=False):
        conn=raw
        try:
            if self.fixture and reset:
                # Consume only a TLS ClientHello, then RST before any HTTP.
                raw.settimeout(1);raw.recv(4096)
                raw.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
                if self.on_initial_connection:self.on_initial_connection()
                return
            if self.fixture:conn=self.contexts[slot].wrap_socket(raw,server_side=True)
            with self.lock:self.sockets.discard(raw);self.sockets.add(conn)
            if self.fixture:self.handshakes[slot]+=1
            data=b''
            while not self.stop.is_set():
                while b'\r\n\r\n' not in data:
                    chunk=conn.recv(4096)
                    if not chunk:return
                    data+=chunk
                    if self.fixture:self.bytes[slot]+=len(chunk)
                head,data=data.split(b'\r\n\r\n',1)
                lines=head.decode().split('\r\n');method,path,_=lines[0].split(' ')
                headers=dict(line.lower().split(': ',1) for line in lines[1:]);length=int(headers.get('content-length','0'))
                while len(data)<length:
                    chunk=conn.recv(4096)
                    if not chunk:return
                    data+=chunk
                    if self.fixture:self.bytes[slot]+=len(chunk)
                body,data=data[:length],data[length:]
                self.handler(self,conn,slot,method,path,headers,body)
                if headers.get('connection','').lower()=='close':return
        except (OSError,ssl.SSLError):pass
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            with self.lock:self.sockets.discard(raw);self.sockets.discard(conn)
            conn.close()
    def close(self):
        self.stop.set();self.socket.close()
        with self.lock:sockets=list(self.sockets)
        for conn in sockets:
            try:conn.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            conn.close()
        self.thread.join(1)
        for t in self.threads:t.join(1)

def send(conn, body, content_type='application/json', status=200, close=False):
    if isinstance(body,(dict,list)):body=json.dumps(body).encode()
    if isinstance(body,str):body=body.encode()
    conn.sendall(f'HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nConnection: {'close' if close else 'keep-alive'}\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body)

def policy(origin):
    return load_gateway_policy({'source':'synthetic-client-policy','version':'1','origins':[origin],'appIds':[APP],'composeHashes':[COMPOSE],'releaseIds':[RELEASE],'keyProviderId':KMS,
        'requireInTeeTls':True,'requirePrivateLogs':True,'requireDigestPinnedImages':True,'requireHardwareVerified':True,'requireEvidenceExpiry':True,'maxEvidenceAgeMs':300000,'acceptableTcbStatuses':['UpToDate'],
        'platform':{'mrTd':['00'*48],'mrConfigId':[SYNTHETIC_MR_CONFIG_ID],'rtmr0':[LOG.rtmr0],'rtmr1':[LOG.rtmr1],'rtmr2':[LOG.rtmr2],'osImageHash':[SYNTHETIC_OS_IMAGE_HASH]}})

def evidence(origin,nonce,pin):
    binding={'v':1,'nonce':nonce,'app_id':APP,'instance_id':INSTANCE,'compose_hash':COMPOSE,'release_id':RELEASE,'origin':origin,'key_alg':'x25519','public_key':'ab'*32,'transport':'in-tee-tls','tls_spki_sha256':pin}
    return {'binding':binding,'quote':build_synthetic_tdx_quote(report_data_hex=gateway_binding_hash(binding),rtmr0=LOG.rtmr0,rtmr1=LOG.rtmr1,rtmr2=LOG.rtmr2,rtmr3=LOG.rtmr3),
        'event_log':LOG.as_json(),'app_compose':MANIFEST,'vm_config':build_vm_config(),'issued_at_ms':int(time.time()*1000)}

# gcp-tdx-native: synthetic registers, verity root and boot key, NOT Google
# firmware values. RTMR3 and owner registers are zero; there is no event log or
# app-compose. The node's per-boot TLS key must be the one on THIS socket.
GCP_RELEASE='sdk-bound-python@gcp-synthetic'
def gcp_policy(origin):
    now=int(time.time()*1000)
    return load_gateway_policy({'platformKind':'gcp-tdx-native','source':'synthetic-gcp-client-policy','version':'1','origins':[origin],
        'releaseTuples':[{'tupleId':'synthetic-gcp','releaseId':GCP_RELEASE,'appId':SYNTHETIC_GCP_VERITY_ROOT,'composeHash':COMPOSE,**SYNTHETIC_GCP_REGISTERS,
            'notBeforeMs':now-60000,'expiresAtMs':now+3600000}],
        'requireInTeeTls':True,'requirePrivateLogs':True,'requireDigestPinnedImages':True,'requireHardwareVerified':True,'requireEvidenceExpiry':True,'maxEvidenceAgeMs':300000,'acceptableTcbStatuses':['UpToDate']})
def gcp_evidence(bound_slot=None,registers=None):
    def build(server,nonce,slot):
        binding={'v':1,'nonce':nonce,'app_id':SYNTHETIC_GCP_VERITY_ROOT,'instance_id':SYNTHETIC_GCP_INSTANCE_ID,'compose_hash':COMPOSE,'release_id':GCP_RELEASE,'origin':server.origin,'key_alg':'ed25519','public_key':SYNTHETIC_GCP_BOOT_KEY,'transport':'in-tee-tls','tls_spki_sha256':server.pins[bound_slot or slot]}
        return {'binding':binding,'quote':build_synthetic_gcp_quote(gateway_binding_hash(binding),**(registers or {})),'issued_at_ms':int(time.time()*1000)}
    return build

class Topology:
    def __init__(self,fixture,*,evidence_for=None,start='a',switch=False,hold=False,stream=False,cancel=None,expiry_stage=None,expiry_advance=300001,media_delay=0,paid_close=False,quote_close=False,provider_close=False,dns_switch=False,initial_resets=0,on_initial_connection=None):
        self.gateway=0;self.nonces=[];self.att=0;self.paid=0;self.content=[];self.control=[];self.gate=threading.Event();self.gateway_seen=threading.Event();self.stream_seen=threading.Event()
        self.spare=None;self.dns_patch=None;self.lookups=0;self.dns_target='127.0.0.1'
        self.cancel=cancel;self.clock=[time.time()];self.clock_patch=patch('time.time',lambda:self.clock[0]) if expiry_stage else None
        if self.clock_patch:self.clock_patch.start()
        def content(server,conn,slot,method,path,headers,raw):
            parsed=urlsplit(path)
            if parsed.path=='/v1/gateway/attestation':
                self.gateway+=1;nonce=parse_qs(parsed.query)['nonce'][0];self.nonces.append(nonce)
                doc=evidence_for(server,nonce,slot) if evidence_for else evidence(server.origin,nonce,server.pins[slot])
                if switch:server.active='b'
                send(conn,doc,close=quote_close);self.dns_target='::1' if dns_switch else self.dns_target;self.gateway_seen.set();return
            self.content.append((parsed.path,slot,headers,raw))
            if parsed.path=='/v1/tee/attestation':
                nonce=json.loads(raw)['nonce'];doc={'provider':'venice','model':MODEL,'upstream_model':MODEL,'privacy_class':'e2ee','protocol':'venice-legacy','evidence':venice_evidence(nonce,MODEL)}
                if expiry_stage=='provider':self.clock[0]+=expiry_advance/1000
                send(conn,doc,close=provider_close)
            elif parsed.path=='/v1/chat/completions':
                request=json.loads(raw)
                for m in request['messages']:assert venice.decrypt(m['content'],ENCLAVE_PRIV)=='synthetic-content-canary'
                pub=headers['x-venice-tee-client-pub-key']
                wire=''.join('data: '+json.dumps({'choices':[{'delta':{'content':venice.encrypt_field(delta,ENCLAVE_PRIV,pub)}}]})+'\n\n' for delta in ['Hello ','E2EE'])
                wire+='data: '+json.dumps({'choices':[{'delta':{},'finish_reason':'stop'}],'usage':{'prompt_tokens':5,'completion_tokens':2,'total_tokens':7}})+'\n\ndata: [DONE]\n\n'
                if stream:
                    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {len(wire.encode())}\r\nConnection: {'close' if paid_close else 'keep-alive'}\r\n\r\n'.encode())
                    for i,frame in enumerate(wire.split('\n\n')):
                        if not frame:continue
                        conn.sendall((frame+'\n\n').encode())
                        if i==0:self.stream_seen.set()
                        time.sleep(.04)
                else:send(conn,wire,'text/event-stream',close=paid_close)
            elif parsed.path=='/v1/images/generations':
                if media_delay:time.sleep(media_delay)
                send(conn,{'created':1,'data':[{'b64_json':'aGVsbG8=','mime_type':'image/png'}]},close=paid_close)
            elif parsed.path=='/v1/audio/speech':send(conn,b'\x01\x02\x03','audio/mpeg',close=paid_close)
            else:send(conn,{},status=404)
        self.content_server=LocalServer(content,fixture,start,initial_resets=initial_resets,on_initial_connection=on_initial_connection)
        if dns_switch:
            port=self.content_server.socket.getsockname()[1]
            self.spare=LocalServer(content,fixture,'b',host='::1',port=port)
            self.content_server.origin=self.spare.origin=f'https://localhost:{port}'
            original=socket.getaddrinfo
            def resolve(host,port,*args,**kwargs):
                if host=='localhost':
                    self.lookups+=1
                    return original(self.dns_target,port,*args,**kwargs)
                return original(host,port,*args,**kwargs)
            self.dns_patch=patch('socket.getaddrinfo',resolve);self.dns_patch.start()
        def control(server,conn,slot,method,path,headers,raw):
            self.control.append((path,headers,raw));payload=json.loads(raw)
            if path=='/v1/inference/attestation-tickets':
                self.att+=1
                if hold:
                    if self.att==2:self.gate.set()
                    self.gate.wait(3)
                send(conn,{'ticket':'synthetic-att'})
            elif path=='/v1/inference/tickets':
                self.paid+=1
                if expiry_stage=='paid':self.clock[0]+=expiry_advance/1000
                send(conn,{**payload,'ticket':f'synthetic-paid-{self.paid}'})
            else:send(conn,{},status=404)
        self.control_server=LocalServer(control)
        self.options={'base_url':self.content_server.origin,'control_base_url':self.control_server.origin,'api_key':'synthetic-control-key','allow_insecure_http':True,'timeout':3,
            'gateway_connection_binding':{'mode':'required','verification':{'policy':policy(self.content_server.origin),'chain_verifier':NativeBoundary()}}}
        self.client=create_client(**self.options)
    def close(self):
        self.gate.set();self.client.close();self.content_server.close();self.control_server.close()
        if self.spare:self.spare.close()
        if self.dns_patch:self.dns_patch.stop()
        if self.clock_patch:self.clock_patch.stop()
    def chat(self, **kwargs):return self.client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32,**kwargs)

class BoundClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=Path(tempfile.mkdtemp(prefix='.python-bound-client-tls-',dir=ROOT))
        def openssl(*args):subprocess.run(['openssl',*args],cwd=cls.fixture,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-subj','/CN=Python bound-client CA','-days','1',
                # Python 3.13+ verifies strictly and requires CA key usage.
                '-addext','keyUsage=critical,keyCertSign,cRLSign')
        for name in ['a','b']:
            openssl('req','-newkey','rsa:2048','-nodes','-keyout',f'{name}.key','-out',f'{name}.csr','-subj',f'/CN={name}')
            (cls.fixture/f'{name}.ext').write_text('subjectAltName=IP:127.0.0.1,DNS:localhost\n')
            openssl('x509','-req','-in',f'{name}.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',f'{name}.pem','-days','1','-extfile',f'{name}.ext')
        for file in cls.fixture.iterdir():file.chmod(0o600)
        cls.env=patch.dict(os.environ,{'SSL_CERT_FILE':str(cls.fixture/'ca.pem')});cls.env.start()
    @classmethod
    def tearDownClass(cls):cls.env.stop();shutil.rmtree(cls.fixture)
    def topology(self,**kwargs):
        t=Topology(self.fixture,**kwargs);self.addCleanup(t.close);return t
    def test_initial_reset_fresh_preparation_once(self):
        t=self.topology(initial_resets=1)
        self.assertEqual(t.chat()['content'],'Hello E2EE')
        self.assertEqual(t.content_server.connections,2);self.assertEqual(t.gateway,1)
        self.assertEqual(t.att,1);self.assertEqual(t.paid,1);self.assertEqual(len(t.content),2)
        self.assertEqual(t.content_server.handshakes['a'],1)
    def test_repeated_initial_reset_two_sockets_zero_tickets(self):
        t=self.topology(initial_resets=10)
        with self.assertRaises(Exception):t.chat()
        self.assertEqual(t.content_server.connections,2);self.assertEqual(t.gateway,0)
        self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
    def test_retry_resolves_current_policy_again(self):
        from dataclasses import replace
        t=self.topology(initial_resets=1);calls=[]
        class Source(SignedGatewayPolicySource):
            def __init__(self):pass
            def resolve(self,origin,*,force_refresh=False):
                calls.append(force_refresh);current=policy(origin)
                if len(calls)==1:current=replace(current,compose_hashes=['ff'*32])
                return {'policy':current,'authority':'synthetic-NOT-signed','sequence':len(calls),'payloadSha256':'ab'*32,'expiresAtMs':time.time()*1000+10000}
        client=create_client(**{**t.options,'gateway_policy_updates':Source(),'gateway_connection_binding':{'mode':'required','verification':{'chain_verifier':NativeBoundary()}}});self.addCleanup(client.close)
        self.assertEqual(client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)['content'],'Hello E2EE')
        self.assertEqual(calls,[False,False]);self.assertEqual(t.content_server.connections,2)
        self.assertEqual(t.gateway,1);self.assertEqual(t.paid,1)
    def test_cancel_during_initial_reset_no_second_socket(self):
        event=threading.Event();t=self.topology(initial_resets=1,on_initial_connection=event.set)
        with self.assertRaises(Exception):t.chat(cancel_event=event)
        self.assertEqual(t.content_server.connections,1);self.assertEqual(t.gateway,0);self.assertEqual(t.att,0)
    def test_one_absolute_preparation_deadline_no_second_socket(self):
        began=time.monotonic();clock=patch('time.monotonic',lambda:began+181)
        t=self.topology(initial_resets=1,on_initial_connection=clock.start);self.addCleanup(clock.stop)
        with self.assertRaises(Exception):t.chat()
        self.assertEqual(t.content_server.connections,1);self.assertEqual(t.gateway,0);self.assertEqual(t.att,0)
    def test_certificate_failure_not_retried(self):
        t=self.topology()
        foreign=LocalServer(lambda *args:self.fail('HTTP after invalid certificate'),self.fixture)
        self.addCleanup(foreign.close)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.fixture/'ca.pem',self.fixture/'ca.key');foreign.contexts['a']=context
        client=create_client(**{**t.options,'base_url':foreign.origin,'gateway_connection_binding':{'mode':'required','verification':{'policy':policy(foreign.origin),'chain_verifier':NativeBoundary()}}})
        self.addCleanup(client.close)
        with self.assertRaises(Exception):client.chat(MODEL,'venice',[{'role':'user','content':'synthetic'}],32)
        self.assertEqual(foreign.connections,1);self.assertEqual(foreign.bytes['a'],0);self.assertEqual(t.att,0)
    def test_a_quote_b_socket_zero_http(self):
        t=self.topology(dns_switch=True)
        self.assertEqual(t.chat()['content'],'Hello E2EE')
        self.assertEqual(t.spare.bytes['b'],0);self.assertEqual(t.spare.handshakes['b'],0)
        self.assertEqual(t.content_server.handshakes['a'],1);self.assertEqual(t.lookups,1)
        self.assertEqual([x[1] for x in t.content],['a','a']);self.assertEqual(t.paid,1)
    def test_approved_b_encrypted_chat(self):
        t=self.topology(start='b');result=t.chat()
        self.assertEqual(result['content'],'Hello E2EE');self.assertEqual(t.paid,1)
        self.assertEqual([x[0] for x in t.content],['/v1/tee/attestation','/v1/chat/completions'])
        self.assertTrue(all(x[1]=='b' and 'authorization' not in x[2] for x in t.content))
        self.assertNotIn(b'synthetic-content-canary',b''.join(x[2] for x in t.control))
        self.assertNotIn(b'synthetic-content-canary',t.content[1][3])
    def test_concurrent_operations_no_shared_pin(self):
        t=self.topology(switch=True,hold=True)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first=pool.submit(t.chat);self.assertTrue(t.gateway_seen.wait(2));second=pool.submit(t.chat)
            results=[]
            for f in [first,second]:
                try:results.append(f.result())
                except Exception:results.append(None)
        self.assertEqual(sum(x is not None for x in results),2);self.assertEqual(t.paid,2);self.assertEqual(len(set(t.nonces)),2)
    def test_bound_image_speech(self):
        t=self.topology(start='b');image=t.client.images.generate(model='synthetic-image',prompt='synthetic-image-canary');audio=t.client.audio.speech.create(model='synthetic-speech',input='synthetic-speech-canary')
        self.assertEqual(audio.audio,b'\x01\x02\x03');self.assertEqual(t.paid,2);self.assertEqual(len(set(t.nonces)),2)
        self.assertEqual([x[0] for x in t.content],['/v1/images/generations','/v1/audio/speech'])
        self.assertNotIn(b'canary',b''.join(x[2] for x in t.control))
    def test_media_replaced_key_no_paid_replay(self):
        t=self.topology(dns_switch=True)
        t.client.images.generate(model='synthetic-image',prompt='synthetic-image')
        self.assertEqual(t.spare.bytes['b'],0);self.assertEqual(t.paid,1);self.assertEqual([x[1] for x in t.content],['a'])
        self.assertEqual(t.lookups,1);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_required_cannot_disable(self):
        t=self.topology()
        with self.assertRaisesRegex(Exception,'cannot disable'):t.chat(require_gateway=False)
        self.assertEqual(t.gateway,0);self.assertEqual(t.att,0)
    def test_custom_httpx_rejected(self):
        t=self.topology()
        with httpx.Client(transport=httpx.MockTransport(lambda r:httpx.Response(200))) as custom:
            with self.assertRaisesRegex(Exception,'custom HTTPX'):create_client(**t.options,http_client=custom)
        self.assertEqual(t.gateway,0)
    def test_invalid_native_quote_boundary(self):
        t=self.topology()
        class Refusing:
            def verify_chain(self,quote,collateral=None):return False,None
        config={**t.options,'gateway_connection_binding':{'mode':'required','verification':{'policy':policy(t.content_server.origin),'chain_verifier':Refusing()}}}
        client=create_client(**config);self.addCleanup(client.close)
        with self.assertRaisesRegex(Exception,'fully verified'):client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
        self.assertEqual(t.att,0)
    def test_expiry_before_paid_mint(self):
        t=self.topology(expiry_stage='provider')
        with self.assertRaisesRegex(Exception,'expired'):t.chat()
        self.assertEqual(t.paid,0);self.assertEqual(len(t.content),1)
    def test_expiry_after_paid_mint(self):
        t=self.topology(expiry_stage='paid')
        with self.assertRaises(Exception):t.chat()
        self.assertEqual(t.paid,1);self.assertEqual(len(t.content),1)
    def test_delayed_stream_lifecycle(self):
        t=self.topology(start='b',stream=True);self.assertEqual(t.chat()['content'],'Hello E2EE');self.assertEqual(t.paid,1)
    def test_stream_cancellation_without_replay(self):
        t=self.topology(start='b',stream=True);event=threading.Event()
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result=pool.submit(t.chat,cancel_event=event);self.assertTrue(t.stream_seen.wait(2));event.set()
            with self.assertRaises(Exception):result.result(2)
        self.assertEqual(t.paid,1);self.assertEqual(len(t.content),2)
    def test_pre_cancel_before_evidence_tickets(self):
        t=self.topology();event=threading.Event();event.set()
        with self.assertRaisesRegex(Exception,'cancelled'):t.chat(cancel_event=event)
        self.assertEqual(t.gateway,0);self.assertEqual(t.att,0)
    def test_invalid_media_before_ticket(self):
        t=self.topology()
        with self.assertRaises(Exception):t.client.images.generate(model='synthetic-image',prompt=b'unsafe')
        self.assertEqual(t.gateway,0);self.assertEqual(t.paid,0)
    def test_all_verification_surfaces_bind_provider_evidence(self):
        t=self.topology(start='b')
        t.client.verify_attestation(MODEL,'venice')
        t.client.verify_route(MODEL,'venice')
        t.client.verify(MODEL,'venice')
        self.assertEqual(t.gateway,3);self.assertEqual(t.att,3);self.assertEqual(t.paid,0)
        self.assertTrue(all(x[0]=='/v1/tee/attestation' and x[1]=='b' and 'authorization' not in x[2] for x in t.content))
    def test_approval_expiry_while_quote_still_fresh(self):
        t=self.topology(start='b',expiry_stage='paid',expiry_advance=101)
        issued=int(time.time()*1000)
        class SourceBoundary(SignedGatewayPolicySource):
            def __init__(self):pass
            def resolve(self,origin,**kwargs):
                # Explicit synthetic source boundary: signature verification is
                # covered separately by the existing authority suite.
                return {'policy':policy(origin),'authority':'synthetic-NOT-signed','sequence':1,'payloadSha256':'ab'*32,'expiresAtMs':issued+100}
        options={**t.options,'gateway_policy_updates':SourceBoundary(),'gateway_connection_binding':{'mode':'required','verification':{'chain_verifier':NativeBoundary()}}}
        client=create_client(**options);self.addCleanup(client.close)
        with self.assertRaises(Exception):client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
        self.assertEqual(t.paid,1);self.assertEqual(len(t.content),1)
    def test_unapproved_compose_refuses_before_tickets(self):
        from dataclasses import replace
        t=self.topology(start='b');unapproved=replace(policy(t.content_server.origin),compose_hashes=['ff'*32])
        client=create_client(**{**t.options,'gateway_connection_binding':{'mode':'required','verification':{'policy':unapproved,'chain_verifier':NativeBoundary()}}});self.addCleanup(client.close)
        with self.assertRaisesRegex(Exception,'fully verified'):client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
        self.assertEqual(t.att,0)
    def test_proxy_environment_is_ignored_for_strong_mode(self):
        t=self.topology(start='b')
        trap=LocalServer(lambda *args:self.fail('proxy received content'));self.addCleanup(trap.close)
        with patch.dict(os.environ,{'HTTP_PROXY':trap.origin,'HTTPS_PROXY':trap.origin,'ALL_PROXY':trap.origin,'NO_PROXY':''}):
            client=create_client(**t.options);self.addCleanup(client.close)
            self.assertEqual(client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)['content'],'Hello E2EE')
    def test_unsafe_override_options_refuse_before_network(self):
        t=self.topology()
        for setting in [{'proxy':'http://127.0.0.1:1'},{'follow_redirects':True},{'transport':httpx.MockTransport(lambda r:httpx.Response(200))}]:
            with self.assertRaises(TypeError):create_client(**t.options,**setting)
        self.assertEqual(t.gateway,0)
    def test_async_verifier_refused_explicitly_before_evidence(self):
        t=self.topology()
        class AsyncBoundary:
            async def prepare(self,*args,**kwargs):return None
        with self.assertRaisesRegex(Exception,'async mode is unsupported'):
            create_client(**{**t.options,'gateway_connection_binding':{'mode':'required','verification':{'policy':policy(t.content_server.origin),'chain_verifier':AsyncBoundary()}}})
        self.assertEqual(t.gateway,0)
    def test_async_transport_refused_before_http(self):
        t=self.topology(start='b')
        async def attempt():
            transport=SpkiBoundGatewayTransport(origin=t.content_server.origin,expected_tls_spki_sha256=t.content_server.pins['b'])
            with self.assertRaises(BoundGatewayTransportError) as error:
                async with httpx.AsyncClient(transport=transport,trust_env=False) as client:
                    await client.post(t.content_server.origin+'/inference',content=b'must-not-arrive')
            self.assertEqual(error.exception.code,'configuration')
            transport.close()
        asyncio.run(attempt());self.assertEqual(t.content_server.bytes['b'],0)
    def test_one_operation_cancel_does_not_close_another(self):
        t=self.topology(start='b',stream=True);event=threading.Event()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first=pool.submit(t.chat,cancel_event=event);self.assertTrue(t.stream_seen.wait(2));second=pool.submit(t.chat);event.set()
            with self.assertRaises(Exception):first.result(2)
            self.assertEqual(second.result(2)['content'],'Hello E2EE')
        self.assertEqual(t.paid,2)
    def test_client_close_cancels_owned_stream_without_replay(self):
        t=self.topology(start='b',stream=True)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            operation=pool.submit(t.chat);self.assertTrue(t.stream_seen.wait(2));t.client.close()
            with self.assertRaises(Exception):operation.result(2)
        self.assertEqual(t.paid,1)
    def test_client_close_during_initial_policy_blocks_even_quote_http(self):
        t=self.topology();entered=threading.Event();release=threading.Event();original=t.client._resolve_gateway_policy
        def pending(*args,**kwargs):
            entered.set();release.wait(2);return original(*args,**kwargs)
        t.client._resolve_gateway_policy=pending
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result=pool.submit(t.chat)
            try:
                self.assertTrue(entered.wait(1));t.client.close()
                self.assertFalse(result.done())  # close does not join foreign policy work.
            finally:release.set()
            with self.assertRaises(Exception):result.result(2)
        self.assertEqual(t.gateway,0);self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
        self.assertEqual(t.content_server.handshakes['a'],0)
    def test_client_close_during_native_prepare_signals_private_operation(self):
        t=self.topology();entered=threading.Event();release=threading.Event();finished=threading.Event();caller=threading.Event()
        class Native(NativeBoundary):
            def prepare(self,quote,**kwargs):
                entered.set();release.wait(2)
                try:return super().prepare(quote,**kwargs)
                finally:finished.set()
        client=create_client(**{**t.options,'gateway_connection_binding':{'mode':'required','verification':{'policy':policy(t.content_server.origin),'chain_verifier':Native()}}});self.addCleanup(client.close)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result=pool.submit(client.chat,MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32,cancel_event=caller)
            try:
                self.assertTrue(entered.wait(1));before=t.content_server.bytes['a'];client.close()
                with self.assertRaises(Exception):result.result(1)
                self.assertFalse(caller.is_set());self.assertFalse(finished.is_set())
                self.assertEqual(t.content_server.bytes['a'],before)
            finally:release.set()
            self.assertTrue(finished.wait(1))
        self.assertEqual(t.gateway,1);self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
    def test_client_close_during_quote_body_stops_owned_socket(self):
        t=self.topology();entered=threading.Event();release=threading.Event();original=t.content_server.handler
        def pending(server,conn,slot,method,path,headers,raw):
            if urlsplit(path).path=='/v1/gateway/attestation':entered.set();release.wait(2)
            return original(server,conn,slot,method,path,headers,raw)
        t.content_server.handler=pending
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result=pool.submit(t.chat)
            try:
                self.assertTrue(entered.wait(1));before=t.content_server.bytes['a'];t.client.close()
                with self.assertRaises(Exception):result.result(1)
                self.assertEqual(t.content_server.bytes['a'],before)
            finally:release.set()
        self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
    def test_client_close_during_policy_refresh_cannot_admit_late_result(self):
        from dataclasses import replace
        t=self.topology();entered=threading.Event();release=threading.Event();finished=threading.Event()
        class Source(SignedGatewayPolicySource):
            def __init__(self):pass
            def resolve(self,origin,force_refresh=False,**kwargs):
                if force_refresh:
                    entered.set();release.wait(2);finished.set()
                current=policy(origin) if force_refresh else replace(policy(origin),compose_hashes=['ff'*32])
                return {'policy':current,'authority':'synthetic-NOT-signed','sequence':2 if force_refresh else 1,'payloadSha256':'ab'*32,'expiresAtMs':time.time()*1000+10000}
        client=create_client(**{**t.options,'gateway_policy_updates':Source(),'gateway_connection_binding':{'mode':'required','verification':{'chain_verifier':NativeBoundary()}}});self.addCleanup(client.close)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result=pool.submit(client.chat,MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
            try:
                self.assertTrue(entered.wait(1));before=t.content_server.bytes['a'];client.close()
                with self.assertRaises(Exception):result.result(1)
                self.assertFalse(finished.is_set());self.assertEqual(t.content_server.bytes['a'],before)
            finally:release.set()
            self.assertTrue(finished.wait(1))
        self.assertEqual(t.gateway,1);self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
    def test_stream_deadline_remains_active_without_retry(self):
        t=self.topology(start='b',stream=True)
        client=create_client(**{**t.options,'timeout':.07});self.addCleanup(client.close)
        with self.assertRaises(Exception):client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
        self.assertEqual(t.paid,1);self.assertEqual(len(t.content),2)
    def test_media_timeout_tightens_owned_transport(self):
        t=self.topology(start='b',media_delay=.15)
        started=time.monotonic()
        with self.assertRaises(Exception):t.client.images.generate(model='synthetic-image',prompt='synthetic-image-canary',timeout=.025)
        self.assertLess(time.monotonic()-started,.5)
        self.assertEqual(t.paid,1);self.assertEqual(len(t.content),1)
    def test_tls_dispatch_guard_writes_zero_http(self):
        t=self.topology(start='b')
        def refuse():raise ValueError('synthetic approval expired after TLS')
        transport=SpkiBoundGatewayTransport(origin=t.content_server.origin,expected_tls_spki_sha256=t.content_server.pins['b'],before_http_dispatch=refuse)
        with httpx.Client(transport=transport,trust_env=False) as client:
            with self.assertRaises(BoundGatewayTransportError) as result:client.post(t.content_server.origin+'/inference',content=b'must-not-arrive')
        self.assertEqual(result.exception.code,'authorization');self.assertEqual(result.exception.dispatch_phase,'before_http');self.assertEqual(t.content_server.bytes['b'],0)

    def test_final_paid_close_wholebody_and_stream(self):
        image=self.topology(dns_switch=True,paid_close=True)
        image.client.images.generate(model='synthetic-image',prompt='synthetic-image')
        self.assertEqual(image.paid,1);self.assertEqual(image.content_server.handshakes['a'],1);self.assertEqual(image.spare.bytes['b'],0)
        stream=self.topology(dns_switch=True,paid_close=True,stream=True)
        self.assertEqual(stream.chat()['content'],'Hello E2EE')
        self.assertEqual(stream.paid,1);self.assertEqual(stream.content_server.handshakes['a'],1);self.assertEqual(stream.spare.bytes['b'],0)
        self.assertEqual([x[1] for x in stream.content],['a','a'])
    def test_refresh_original_quote_preserves_provenance_and_immutable_raw_report(self):
        from dataclasses import replace
        t=self.topology(dns_switch=True);origin=t.content_server.origin;issued=time.time()*1000;calls=[];prepared=[]
        class Native(NativeBoundary):
            def prepare(self,quote,**kwargs):prepared.append(quote);return super().prepare(quote,**kwargs)
        class Source(SignedGatewayPolicySource):
            def __init__(self):pass
            def resolve(self,origin,force_refresh=False,**kwargs):
                calls.append(force_refresh)
                current=policy(origin) if force_refresh else replace(policy(origin),compose_hashes=['ff'*32])
                return {'policy':current,'authority':'synthetic-NOT-signed','sequence':2 if force_refresh else 1,'payloadSha256':('aa' if force_refresh else 'ab')*32,'expiresAtMs':issued+10000}
        client=create_client(**{**t.options,'gateway_policy_updates':Source(),'gateway_connection_binding':{'mode':'required','verification':{'chain_verifier':Native()}}});self.addCleanup(client.close)
        report=client.verify(MODEL,'venice')
        self.assertTrue(report['trusted']);self.assertEqual(report['gateway']['policy']['sequence'],2);self.assertEqual(report['gateway']['policy']['expiresAtMs'],issued+10000)
        self.assertEqual(calls,[False,True]);self.assertEqual(len(prepared),1);self.assertEqual(t.gateway,1);self.assertEqual(t.lookups,1)
        self.assertEqual(t.content_server.handshakes['a'],1);self.assertEqual(t.spare.bytes['b'],0)
        with self.assertRaises(TypeError):report['gateway']['raw_evidence']['binding']['nonce']='wrong'
        gateway=report['gateway'];verdict=gateway['verdict']
        for mutate in [lambda:gateway.__setitem__('status','failed'),lambda:gateway['policy'].__setitem__('sequence',99),
                       lambda:setattr(verdict,'status','failed'),lambda:setattr(verdict.binding,'nonce','wrong'),
                       lambda:setattr(verdict.checks[0],'passed',False),lambda:verdict.measurements.__setitem__('mrTd','wrong'),
                       lambda:verdict.as_dict()['binding'].__setitem__('nonce','wrong'),
                       lambda:verdict.as_dict()['checks'][0].__setitem__('passed',False)]:
            with self.assertRaises(TypeError):mutate()
        self.assertIsInstance(verdict.checks,tuple)
        self.assertEqual(json.loads(json.dumps(verdict.as_dict()))['status'],'ok')
        self.assertEqual(json.loads(json.dumps(gateway['raw_evidence']))['binding']['nonce'],verdict.binding.nonce)
        self.assertEqual(verdict.status,'ok');self.assertEqual(gateway['policy']['sequence'],2)
        self.assertEqual(t.paid,0)
    def test_refreshed_downgrade_or_expiry_before_tickets(self):
        from dataclasses import replace
        for mode in ['downgrade','expiry']:
            with self.subTest(mode=mode):
                t=self.topology();issued=time.time()*1000
                class Source(SignedGatewayPolicySource):
                    def __init__(self):pass
                    def resolve(self,origin,force_refresh=False,**kwargs):
                        current=replace(policy(origin),compose_hashes=['ff'*32]) if not force_refresh else replace(policy(origin),require_hardware_verified=mode!='downgrade')
                        return {'policy':current,'authority':'synthetic-NOT-signed','sequence':2 if force_refresh else 1,'payloadSha256':'ab'*32,'expiresAtMs':issued-1 if force_refresh and mode=='expiry' else issued+10000}
                client=create_client(**{**t.options,'gateway_policy_updates':Source(),'gateway_connection_binding':{'mode':'required','verification':{'chain_verifier':NativeBoundary()}}});self.addCleanup(client.close)
                with self.assertRaises(Exception):client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
                self.assertEqual(t.gateway,1);self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])

    def gcp_client(self,t,pilot=True):
        verification={'policy':gcp_policy(t.content_server.origin),'chain_verifier':NativeBoundary(),**({'unqualified_platform_pilot':True} if pilot else {})}
        client=create_client(**{**t.options,'gateway_connection_binding':{'mode':'required','verification':verification}});self.addCleanup(client.close)
        return client
    def gcp_chat(self,client):return client.chat(MODEL,'venice',[{'role':'user','content':'synthetic-content-canary'}],32)
    def test_gcp_pilot_retained_socket_key_matches_quote(self):
        t=self.topology(evidence_for=gcp_evidence())
        self.assertEqual(self.gcp_chat(self.gcp_client(t))['content'],'Hello E2EE')
        self.assertEqual(t.gateway,1);self.assertEqual(t.content_server.handshakes,{'a':1,'b':0})
        self.assertEqual([slot for _,slot,_,_ in t.content],['a','a'])
    def test_gcp_wrong_key_zero_tickets_zero_content(self):
        t=self.topology(evidence_for=gcp_evidence(bound_slot='b'))
        with self.assertRaises(Exception):self.gcp_chat(self.gcp_client(t))
        self.assertEqual(t.gateway,1);self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
    def test_gcp_wrong_platform_tuple_zero_tickets_zero_content(self):
        t=self.topology(evidence_for=gcp_evidence(registers={'mrTd':'5e'*48}))
        with self.assertRaises(Exception):self.gcp_chat(self.gcp_client(t))
        self.assertEqual(t.att,0);self.assertEqual(t.paid,0);self.assertEqual(t.content,[])
    def test_gcp_without_pilot_refused_before_any_connection(self):
        t=self.topology(evidence_for=gcp_evidence())
        with self.assertRaises(Exception):self.gcp_chat(self.gcp_client(t,pilot=False))
        self.assertEqual(t.content_server.connections,0);self.assertEqual(t.gateway,0);self.assertEqual(t.att,0);self.assertEqual(t.content,[])

if __name__=='__main__':unittest.main(verbosity=2)
