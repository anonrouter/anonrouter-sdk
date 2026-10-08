"""Real TLS retained-channel tests; native DCAP/source ports are SYNTHETIC.

No external DNS/HTTP, paid tickets or inference. Installed-wheel selection is
inherited from the client acceptance harness via SDK_BOUND_INSTALLED=1.
"""
from __future__ import annotations
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('retained_fixture_helpers',Path(__file__).with_name('python-bound-client-tests.py'))
helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
from anonrouter_confidential.gateway import retained_sync as retained
from anonrouter_confidential.gateway.transport_sync import BoundGatewayTransportError

class RetainedTests(unittest.TestCase):
    def test_public_error_codes_cannot_mint_initial_retry(self):
        self.assertFalse(retained.consume_initial_connection_refusal(BoundGatewayTransportError('timeout','synthetic')))
        self.assertFalse(retained.consume_initial_connection_refusal(BoundGatewayTransportError('tls_certificate','synthetic')))
        class Forged(BoundGatewayTransportError):
            __hash__=None
        self.assertFalse(retained.consume_initial_connection_refusal(Forged('timeout','synthetic')))
    def test_initial_dns_is_joined_before_failed_preparation_returns(self):
        t=self.topology();original=socket.getaddrinfo;completed=threading.Event()
        def slow(*args,**kwargs):
            time.sleep(.06);result=original(*args,**kwargs);completed.set();return result
        with patch.object(socket,'getaddrinfo',slow):
            with self.assertRaises(Exception):self.open(t,pre_dispatch_budget=.02)
        self.assertTrue(completed.is_set());self.assertEqual(t.content_server.connections,0)
        self.assertEqual(t.gateway,0);self.assertEqual(t.att,0)
    def test_initial_tls_timeout_mints_single_consumable_joined_refusal(self):
        silent=helpers.LocalServer(lambda *args:self.fail('HTTP reached silent TLS fixture'))
        self.addCleanup(silent.close)
        origin=silent.origin.replace('http:','https:')
        with self.assertRaises(BoundGatewayTransportError) as refused:
            retained.RetainedGatewayConnection(origin=origin,policy=helpers.policy(origin),chain_verifier=helpers.NativeBoundary(),timeout=.04)
        self.assertTrue(retained.consume_initial_connection_refusal(refused.exception))
        self.assertFalse(retained.consume_initial_connection_refusal(refused.exception))
        self.assertEqual(silent.connections,1)
    @classmethod
    def setUpClass(cls):
        helpers.BoundClientTests.setUpClass.__func__(cls)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout','foreign.key','-out','foreign.pem','-subj','/CN=Untrusted local CA','-days','1'],cwd=cls.fixture,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (cls.fixture/'foreign.key').chmod(0o600);(cls.fixture/'foreign.pem').chmod(0o600)
    @classmethod
    def tearDownClass(cls):helpers.BoundClientTests.tearDownClass.__func__(cls)
    def topology(self,**kwargs):
        t=helpers.Topology(self.fixture,**kwargs);self.addCleanup(t.close);return t
    def open(self,t,**kwargs):
        op=retained.RetainedGatewayConnection(origin=t.content_server.origin,policy=helpers.policy(t.content_server.origin),chain_verifier=helpers.NativeBoundary(),timeout=3,**kwargs)
        self.addCleanup(op.close);return op
    def image(self,t,op):return op.http.post(t.content_server.origin+'/v1/images/generations',json={'prompt':'synthetic'})
    def test_dns_switch_same_socket_quote_provider_paid(self):
        t=self.topology(dns_switch=True);op=self.open(t)
        op.http.post(t.content_server.origin+'/v1/tee/attestation',json={'nonce':op.identity.nonce})
        self.assertEqual(self.image(t,op).status_code,200)
        self.assertEqual(t.content_server.handshakes,{'a':1,'b':0});self.assertEqual(t.spare.handshakes,{'a':0,'b':0});self.assertEqual(t.spare.bytes['b'],0);self.assertEqual(t.lookups,1)
        self.assertEqual([x[1] for x in t.content],['a','a'])
    def test_independent_a_b_operations(self):
        t=self.topology(switch=True);a=self.open(t);b=self.open(t)
        self.assertEqual(a.identity.tls_spki_sha256,t.content_server.pins['a']);self.assertEqual(b.identity.tls_spki_sha256,t.content_server.pins['b'])
        self.assertEqual(self.image(t,a).status_code,200);self.assertEqual(self.image(t,b).status_code,200)
        self.assertEqual(t.content_server.handshakes,{'a':1,'b':1});self.assertEqual([x[1] for x in t.content],['a','b'])
    def test_wrong_nonce_stale_and_spki_mismatch_no_content(self):
        original=helpers.evidence
        for mode in ['nonce','stale','pin']:
            with self.subTest(mode=mode):
                t=self.topology()
                def corrupt(origin,nonce,pin):
                    doc=original(origin,'00'*32 if mode=='nonce' else nonce,'ff'*32 if mode=='pin' else pin)
                    if mode=='stale':doc['issued_at_ms']=1
                    return doc
                with patch.object(helpers,'evidence',corrupt):
                    with self.assertRaises(Exception):self.open(t)
                self.assertEqual(t.gateway,1);self.assertEqual(t.att,0);self.assertEqual(t.content,[]);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_unapproved_compose_and_native_refusal(self):
        t=self.topology();wrong=replace(helpers.policy(t.content_server.origin),compose_hashes=['ff'*32])
        with self.assertRaises(Exception):retained.RetainedGatewayConnection(origin=t.content_server.origin,policy=wrong,chain_verifier=helpers.NativeBoundary(),timeout=3)
        class Refuse:
            def verify_chain(self,*args,**kwargs):return False,None
        with self.assertRaises(Exception):retained.RetainedGatewayConnection(origin=t.content_server.origin,policy=helpers.policy(t.content_server.origin),chain_verifier=Refuse(),timeout=3)
        self.assertEqual(t.content,[]);self.assertEqual(t.gateway,2)
    def test_socket_lost_during_native_prepare_never_reconnects(self):
        t=self.topology(dns_switch=True)
        class Native(helpers.NativeBoundary):
            def prepare(self,quote,**kwargs):
                with t.content_server.lock:connections=list(t.content_server.sockets)
                for conn in connections:conn.shutdown(socket.SHUT_RDWR);conn.close()
                time.sleep(.03)
                return super().prepare(quote,**kwargs)
        with self.assertRaises(Exception):retained.RetainedGatewayConnection(origin=t.content_server.origin,policy=helpers.policy(t.content_server.origin),chain_verifier=Native(),timeout=3)
        self.assertEqual(t.lookups,1);self.assertEqual(t.content_server.handshakes['a'],1);self.assertEqual(t.spare.handshakes['b'],0);self.assertEqual(t.content,[])
    def test_quote_and_provider_close_refuse_reuse(self):
        t=self.topology(quote_close=True)
        with self.assertRaises(Exception):self.open(t)
        self.assertEqual(t.content,[])
        p=self.topology(provider_close=True);op=self.open(p)
        with self.assertRaises(Exception):op.http.post(p.content_server.origin+'/v1/tee/attestation',json={'nonce':op.identity.nonce})
        with self.assertRaises(Exception):self.image(p,op)
        self.assertEqual([x[0] for x in p.content],['/v1/tee/attestation']);self.assertEqual(p.content_server.handshakes['a'],1)
    def test_paid_wholebody_close_consumed_without_replay(self):
        t=self.topology(paid_close=True);op=self.open(t)
        self.assertEqual(self.image(t,op).json()['data'][0]['b64_json'],'aGVsbG8=')
        with self.assertRaises(Exception):self.image(t,op)
        self.assertEqual(len(t.content),1);self.assertEqual(t.content_server.handshakes['a'],1)
    def slow_image(self,t,closed=False,delay=.25):
        original=t.content_server.handler
        def handler(server,conn,slot,method,path,headers,raw):
            if path!='/v1/images/generations':return original(server,conn,slot,method,path,headers,raw)
            t.content.append((path,slot,headers,raw));first=b'data: first\n\n';last=b'data: [DONE]\n\n'
            conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {len(first)+len(last)}\r\nConnection: {"close" if closed else "keep-alive"}\r\n\r\n'.encode()+first)
            t.stream_seen.set();time.sleep(delay);conn.sendall(last)
        t.content_server.handler=handler
    def test_paid_close_stream_done_after_predispatch_expiry(self):
        t=self.topology();self.slow_image(t,closed=True)
        op=self.open(t,pre_dispatch_budget=.15)
        with op.http.stream('POST',t.content_server.origin+'/v1/images/generations',json={'prompt':'synthetic'}) as response:
            self.assertEqual(b''.join(response.iter_bytes()),b'data: first\n\ndata: [DONE]\n\n')
        with self.assertRaises(Exception):self.image(t,op)
        self.assertEqual(len(t.content),1);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_stream_cancel_owns_socket(self):
        t=self.topology();self.slow_image(t);event=threading.Event();op=self.open(t,cancel_event=event)
        with op.http.stream('POST',t.content_server.origin+'/v1/images/generations',json={'prompt':'synthetic'}) as response:
            it=response.iter_bytes();self.assertIn(b'first',next(it));event.set()
            with self.assertRaises(Exception):list(it)
        with self.assertRaises(Exception):self.image(t,op)
        self.assertEqual(len(t.content),1);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_idle_socket_loss_refuses_guard_and_never_reconnects(self):
        t=self.topology(dns_switch=True);op=self.open(t)
        with t.content_server.lock:connections=list(t.content_server.sockets)
        for conn in connections:
            conn.shutdown(socket.SHUT_RDWR);conn.close()
        time.sleep(.02);tickets=0
        with self.assertRaises(Exception):op.assert_dispatch_allowed();tickets+=1
        with self.assertRaises(Exception):self.image(t,op)
        self.assertEqual(tickets,0);self.assertEqual(t.lookups,1);self.assertEqual(t.spare.bytes['b'],0);self.assertEqual(t.content,[])
    def test_reuse_expiry_and_cancel_guard_zero_new_http(self):
        original=retained._Stream.write
        for mode in ['expiry','cancel']:
            with self.subTest(mode=mode):
                t=self.topology();event=threading.Event();expires=time.time()*1000+10000;op=self.open(t,cancel_event=event,approval_expires_at_ms=expires);before=t.content_server.bytes['a']
                def race(stream,buffer,timeout=None):
                    if buffer.startswith(b'POST '):
                        if mode=='cancel':event.set();return original(stream,buffer,timeout)
                        with patch('time.time',lambda:expires/1000+1):return original(stream,buffer,timeout)
                    return original(stream,buffer,timeout)
                with patch.object(retained._Stream,'write',race):
                    with self.assertRaises(Exception):self.image(t,op)
                time.sleep(.01);self.assertEqual(t.content_server.bytes['a'],before);self.assertEqual(t.content,[]);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_expired_budget_and_operation_close_block_future_http(self):
        t=self.topology();op=self.open(t,pre_dispatch_budget=.12);before=t.content_server.bytes['a'];time.sleep(.13)
        with self.assertRaises(Exception):self.image(t,op)
        self.assertEqual(t.content_server.bytes['a'],before)
        p=self.topology();closed=self.open(p);closed.close()
        with self.assertRaises(Exception):self.image(p,closed)
        self.assertEqual(p.content_server.handshakes['a'],1);self.assertEqual(p.content,[])
    def test_response_owns_busy_sequential_channel(self):
        t=self.topology();op=self.open(t)
        with op.http.stream('POST',t.content_server.origin+'/v1/tee/attestation',json={'nonce':op.identity.nonce}) as response:
            with self.assertRaises(BoundGatewayTransportError) as error:self.image(t,op)
            self.assertEqual(error.exception.code,'busy');response.read()
        self.assertEqual(self.image(t,op).status_code,200);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_origin_headers_and_extensions_refused(self):
        t=self.topology();op=self.open(t);before=t.content_server.bytes['a']
        for url,headers,extensions in [('https://outside.invalid/v1/images/generations',{},{}),(t.content_server.origin+'/v1/images/generations',{'authorization':'must-not-arrive'},{}),(t.content_server.origin+'/v1/images/generations',{'connection':'close'},{}),(t.content_server.origin+'/v1/images/generations',{}, {'sni_hostname':'outside.invalid'})]:
            with self.assertRaises(Exception):op.http.post(url,json={'prompt':'synthetic'},headers=headers,extensions=extensions)
        self.assertEqual(t.content_server.bytes['a'],before);self.assertEqual(t.content,[])
    def test_normal_ca_and_hostname_before_http(self):
        t=self.topology()
        with self.assertRaises(Exception):self.open(t,ca_pem=(self.fixture/'foreign.pem').read_text())
        self.assertEqual(t.gateway,0);self.assertEqual(t.content_server.bytes['a'],0)
        p=self.topology();port=p.content_server.socket.getsockname()[1];origin=f'https://wrong.invalid:{port}';original=socket.getaddrinfo
        with patch('socket.getaddrinfo',lambda host,port,*a,**kw:original('127.0.0.1' if host=='wrong.invalid' else host,port,*a,**kw)):
            with self.assertRaises(Exception):retained.RetainedGatewayConnection(origin=origin,policy=helpers.policy(origin),chain_verifier=helpers.NativeBoundary(),timeout=3)
        self.assertEqual(p.gateway,0);self.assertEqual(p.content_server.bytes['a'],0)
    def test_refresh_same_evidence_pin_and_immutable_report(self):
        t=self.topology(dns_switch=True);origin=t.content_server.origin;old=replace(helpers.policy(origin),compose_hashes=['ff'*32]);counts={'prepare':0,'refresh':0}
        class Native(helpers.NativeBoundary):
            def prepare(self,quote,**kwargs):counts['prepare']+=1;return super().prepare(quote,**kwargs)
        def refresh():counts['refresh']+=1;return helpers.policy(origin),time.time()*1000+10000
        op=retained.RetainedGatewayConnection(origin=origin,policy=old,chain_verifier=Native(),timeout=3,refresh_policy=refresh);self.addCleanup(op.close)
        self.assertEqual(counts,{'prepare':1,'refresh':1});self.assertEqual(t.gateway,1);self.assertEqual(t.lookups,1)
        for mutate in [lambda:op.raw_evidence.__setitem__('quote','wrong'),lambda:op.raw_evidence['binding'].__setitem__('nonce','wrong'),lambda:op.raw_evidence.pop('binding')]:
            with self.assertRaises(TypeError):mutate()
        for mutate in [lambda:setattr(op.verdict,'status','failed'),lambda:setattr(op.verdict.binding,'tls_spki_sha256','ff'*32),
                       lambda:setattr(op.verdict.checks[0],'passed',False),lambda:op.verdict.as_dict()['binding'].__setitem__('nonce','wrong')]:
            with self.assertRaises(TypeError):mutate()
        for name in ['verdict','raw_evidence','identity']:
            with self.assertRaises(AttributeError):setattr(op,name,None)
        op.report={'policy':{'sequence':2},'verdict':op.verdict,'raw_evidence':op.raw_evidence}
        with self.assertRaises(TypeError):op.report['policy']['sequence']=99
        with self.assertRaises(TypeError):op.report={}
        self.assertEqual(json.loads(json.dumps(op.verdict.as_dict()))['status'],'ok')
        json.dumps(op.raw_evidence);self.assertEqual(self.image(t,op).status_code,200);self.assertEqual(t.spare.bytes['b'],0)
    def test_refresh_downgrade_and_expiry_refused(self):
        for mode in ['downgrade','expiry','verdict','unbounded']:
            with self.subTest(mode=mode):
                t=self.topology();origin=t.content_server.origin;old=replace(helpers.policy(origin),compose_hashes=['ff'*32])
                def refresh():
                    if mode=='verdict':return {'policy':helpers.policy(origin),'verdict':{'status':'ok'}}
                    # 'unbounded': a bounded approval refreshed with no expiry at all.
                    if mode=='unbounded':return helpers.policy(origin), None
                    return replace(helpers.policy(origin),require_hardware_verified=mode!='downgrade'), time.time()*1000-1 if mode=='expiry' else time.time()*1000+10000
                with self.assertRaises(Exception):retained.RetainedGatewayConnection(origin=origin,policy=old,chain_verifier=helpers.NativeBoundary(),timeout=3,refresh_policy=refresh,approval_expires_at_ms=time.time()*1000+60000)
                self.assertEqual(t.gateway,1);self.assertEqual(t.content,[])
    def test_blocked_verifier_refresh_and_cancel_bounded(self):
        for mode in ['native','refresh','cancel']:
            with self.subTest(mode=mode):
                t=self.topology();origin=t.content_server.origin;event=threading.Event()
                class Slow(helpers.NativeBoundary):
                    def prepare(self,quote,**kwargs):time.sleep(.3);return super().prepare(quote,**kwargs)
                old=replace(helpers.policy(origin),compose_hashes=['ff'*32]) if mode=='refresh' else helpers.policy(origin)
                def refresh():time.sleep(.3);return helpers.policy(origin),None
                if mode=='cancel':threading.Timer(.04,event.set).start()
                started=time.monotonic()
                with self.assertRaises(Exception):retained.RetainedGatewayConnection(origin=origin,policy=old,chain_verifier=helpers.NativeBoundary() if mode=='refresh' else Slow(),timeout=3,pre_dispatch_budget=.12,cancel_event=event,refresh_policy=refresh if mode=='refresh' else None)
                self.assertLess(time.monotonic()-started,.25);self.assertEqual(t.content,[]);self.assertEqual(t.content_server.handshakes['a'],1)
    def test_async_adapter_refuses_without_additional_http(self):
        t=self.topology();op=self.open(t);before=t.content_server.bytes['a']
        async def attempt():
            with self.assertRaises(BoundGatewayTransportError) as result:
                async with helpers.httpx.AsyncClient(transport=op._transport,trust_env=False) as client:
                    await client.post(t.content_server.origin+'/v1/images/generations',json={'prompt':'synthetic'})
            self.assertEqual(result.exception.code,'configuration')
        asyncio.run(attempt());self.assertEqual(t.content_server.bytes['a'],before);self.assertEqual(t.content,[])
    def test_evidence_size_bound_and_exact_versions(self):
        t=self.topology();original=helpers.evidence
        def huge(*args):doc=original(*args);doc['padding']='x'*2097152;return doc
        with patch.object(helpers,'evidence',huge):
            with self.assertRaises(Exception):self.open(t)
        self.assertEqual(t.gateway,1);self.assertEqual(t.content,[])
        p=self.topology()
        with patch.object(retained.httpcore,'__version__','unreviewed'):
            with self.assertRaises(Exception):self.open(p)
        self.assertEqual(p.gateway,0)

if __name__=='__main__':unittest.main(verbosity=2)
