"""Real synthetic TLS; no production calls or mocked trust decisions."""
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("transport_sync", ROOT / "python/src/anonrouter_confidential/gateway/transport_sync.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SpkiBoundGatewayTransport, BoundGatewayTransportError = module.SpkiBoundGatewayTransport, module.BoundGatewayTransportError


class Server:
    def __init__(self, fixture, name, handler=None, stall=False):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(fixture / f"{name}.pem", fixture / f"{name}.key")
        certificate = x509.load_pem_x509_certificate((fixture / f"{name}.pem").read_bytes())
        self.pin = hashlib.sha256(certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.name, self.handler, self.stall = name, handler, stall
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.05)
        self.origin = f"https://127.0.0.1:{self.socket.getsockname()[1]}"
        self.stop = threading.Event()
        self.http_bytes, self.requests, self.connections = 0, [], 0
        self.sockets, self.workers = set(), []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.socket.accept()
            except (TimeoutError, OSError):
                continue
            with self.lock:
                self.sockets.add(raw)
                self.connections += 1
            worker = threading.Thread(target=self.handle, args=(raw,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def handle(self, raw):
        conn = raw
        try:
            if self.stall:
                while not self.stop.is_set() and raw.recv(4096):
                    pass
                return
            conn = self.context.wrap_socket(raw, server_side=True)
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.add(conn)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                with self.lock:
                    self.http_bytes += len(chunk)
                data += chunk
            headers, body = data.split(b"\r\n\r\n", 1)
            length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
            while len(body) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                with self.lock:
                    self.http_bytes += len(chunk)
                body += chunk
            with self.lock:
                self.requests.append((headers, body))
            if self.handler:
                self.handler(self, conn)
            else:
                result = json.dumps({"slot": self.name}).encode()
                conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: " + str(len(result)).encode() + b"\r\n\r\n" + result)
        except (OSError, ssl.SSLError):
            pass
        finally:
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.discard(conn)
            conn.close()

    def close(self):
        self.stop.set()
        self.socket.close()
        with self.lock:
            sockets = list(self.sockets)
        for conn in sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        self.thread.join(1)
        for worker in self.workers:
            worker.join(1)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Path(tempfile.mkdtemp(prefix=".synthetic-python-tls-", dir=ROOT))
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.fixture, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=SDK local Python test CA", "-days", "1")
        cls.ca = (cls.fixture / "ca.pem").read_text()
        for name in ["a", "b", "wrong-host"]:
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}")
            (cls.fixture / f"{name}.ext").write_text("subjectAltName=" + ("DNS:wrong.example" if name == "wrong-host" else "IP:127.0.0.1,DNS:localhost") + "\n")
            openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", "1", "-extfile", f"{name}.ext")
        for file in cls.fixture.iterdir():
            file.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.fixture)

    def setUp(self):
        self.servers, self.clients = [], []

    def tearDown(self):
        for client in self.clients:
            client.close()
        for server in self.servers:
            server.close()

    def server(self, name, **kwargs):
        result = Server(self.fixture, name, **kwargs)
        self.servers.append(result)
        return result

    def client(self, target, **kwargs):
        options = {"origin": target.origin, "expected_tls_spki_sha256": target.pin, "ca_pem": self.ca, "request_timeout": 2.0, **kwargs}
        transport = SpkiBoundGatewayTransport(**options)
        client = httpx.Client(transport=transport, trust_env=False, follow_redirects=True)
        self.clients.append(client)
        return client

    def refuses(self, code):
        return self.assertRaisesRegex(BoundGatewayTransportError, rf"\({code}\)")

    def test_a_pin_b_receives_zero_http_bytes(self):
        a, b = self.server("a"), self.server("b")
        client = self.client(b, expected_tls_spki_sha256=a.pin)
        with self.refuses("tls_pin_mismatch") as failure:
            client.post(b.origin + "/inference", content=b"must-not-arrive", headers={"x-test-ticket": "synthetic"})
        self.assertEqual(failure.exception.dispatch_phase, "before_http")
        time.sleep(0.02)
        self.assertEqual(b.http_bytes, 0)
        self.assertEqual(b.requests, [])

    def test_approved_b_succeeds(self):
        b = self.server("b")
        response = self.client(b).post(b.origin + "/inference", content=b"synthetic")
        self.assertEqual(response.json(), {"slot": "b"})
        self.assertEqual(len(b.requests), 1)
        self.assertEqual(b.requests[0][1], b"synthetic")

    def test_hostname_and_ca_cannot_be_bypassed_by_matching_pin(self):
        bad = self.server("wrong-host")
        b = self.server("b")
        for target, client in [(bad, self.client(bad)), (b, self.client(b, ca_pem=None))]:
            with self.refuses("tls_certificate"):
                client.post(target.origin + "/inference", content=b"must-not-arrive")
            self.assertEqual(target.http_bytes, 0)
            self.assertEqual(target.requests, [])

    def test_concurrency_uses_fresh_isolated_pools(self):
        a, b = self.server("a"), self.server("b")
        ca, cb = self.client(a), self.client(b)
        def send(index):
            target, client = (a, ca) if index % 2 else (b, cb)
            return client.post(target.origin + "/inference", content=f"synthetic-{index}").json()["slot"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(send, range(12)))
        self.assertEqual(results, ["a" if index % 2 else "b" for index in range(12)])
        self.assertEqual(len(a.requests), 6)
        self.assertEqual(len(b.requests), 6)
        self.assertEqual(a.connections, 6)
        self.assertEqual(b.connections, 6)

    def test_generic_pool_cannot_bypass_pin(self):
        def keep_alive(server, conn):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            server.stop.wait()
        a, b = self.server("a"), self.server("b", handler=keep_alive)
        context = ssl.create_default_context(cadata=self.ca)
        with httpx.Client(verify=context, trust_env=False) as ordinary:
            self.assertEqual(ordinary.get(b.origin).status_code, 200)
            self.assertEqual(len(ordinary._transport._pool.connections), 1)
            self.assertTrue(ordinary._transport._pool.connections[0].is_idle())
            before = b.http_bytes
            with self.refuses("tls_pin_mismatch"):
                self.client(b, expected_tls_spki_sha256=a.pin).post(b.origin, content=b"must-not-arrive")
            self.assertEqual(len(b.requests), 1)
            self.assertEqual(b.http_bytes, before)

    def test_redirects_refuse_even_when_httpx_follow_redirects_enabled(self):
        b = self.server("b")
        a = self.server("a", handler=lambda server, conn: conn.sendall(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: " + (b.origin + "/redirect-target").encode() + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
        with self.refuses("redirect"):
            self.client(a).post(a.origin, content=b"synthetic")
        self.assertEqual(b.http_bytes, 0)
        self.assertEqual(b.requests, [])

    def test_origin_and_unsafe_sni_host_framing_overrides_refuse(self):
        a, b = self.server("a"), self.server("b")
        client = self.client(a)
        with self.refuses("configuration"):
            client.post(b.origin, content=b"must-not-arrive")
        for kwargs in [{"extensions": {"sni_hostname": "wrong.example"}}, {"headers": {"host": "wrong.example"}}, {"headers": {"content-length": "999"}}, {"headers": {"transfer-encoding": "chunked"}}]:
            with self.refuses("configuration"):
                client.post(a.origin, content=b"must-not-arrive", **kwargs)
        self.assertEqual(a.http_bytes, 0)
        self.assertEqual(b.http_bytes, 0)

    @staticmethod
    def stream_handler(server, conn):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: started\n\n")
        if not server.stop.wait(0.04):
            conn.sendall(b"data: continued\n\n")
        if not server.stop.wait(0.04):
            conn.sendall(b"data: [DONE]\n\n")

    @staticmethod
    def endless_handler(server, conn):
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfirst")
        server.stop.wait(1)

    def test_stream_finishes_normally_without_buffering_all_before_headers(self):
        a = self.server("a", handler=self.stream_handler)
        with self.client(a).stream("GET", a.origin) as response:
            chunks = response.iter_bytes()
            self.assertIn(b"started", next(chunks))
            rest = b"".join(chunks)
            self.assertIn(b"continued", rest)
            self.assertIn(b"[DONE]", rest)
        self.assertEqual(len(a.requests), 1)

    def test_abort_during_stream_closes_and_never_retries(self):
        a = self.server("a", handler=self.endless_handler)
        event = threading.Event()
        client = self.client(a)
        with client.stream("GET", a.origin, extensions={"bound_gateway_cancel": event}) as response:
            chunks = response.iter_bytes()
            self.assertEqual(next(chunks), b"first")
            event.set()
            with self.refuses("cancelled"):
                next(chunks)
        self.assertEqual(len(a.requests), 1)

    def test_body_close_cleans_up_operation_and_transport_close_refuses_reuse(self):
        a = self.server("a", handler=self.endless_handler)
        client = self.client(a)
        with client.stream("GET", a.origin) as response:
            self.assertEqual(next(response.iter_bytes()), b"first")
        self.assertEqual(len(client._transport.pending), 0)
        client._transport.close()
        with self.refuses("cancelled"):
            client.get(a.origin)
        self.assertEqual(len(a.requests), 1)

    def test_transport_close_cancels_an_active_response_stream(self):
        a = self.server("a", handler=self.endless_handler)
        client = self.client(a)
        with client.stream("GET", a.origin) as response:
            chunks = response.iter_bytes()
            self.assertEqual(next(chunks), b"first")
            client._transport.close()
            with self.refuses("cancelled"):
                next(chunks)
        self.assertEqual(len(a.requests), 1)

    def test_pre_abort_sends_nothing(self):
        a = self.server("a")
        event = threading.Event()
        event.set()
        with self.refuses("cancelled"):
            self.client(a).post(a.origin, content=b"must-not-arrive", extensions={"bound_gateway_cancel": event})
        self.assertEqual(a.http_bytes, 0)

    def test_abort_during_handshake_is_owned_and_closes(self):
        a = self.server("a", stall=True)
        event = threading.Event()
        client = self.client(a)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(client.post, a.origin, content=b"must-not-arrive", extensions={"bound_gateway_cancel": event})
            time.sleep(0.05)
            event.set()
            with self.refuses("cancelled"):
                future.result(timeout=0.5)
        self.assertEqual(a.http_bytes, 0)
        self.assertEqual(a.requests, [])

    def test_deadline_covers_stream_and_no_replay(self):
        a = self.server("a", handler=self.endless_handler)
        client = self.client(a, request_timeout=0.08)
        with client.stream("GET", a.origin) as response:
            chunks = response.iter_bytes()
            self.assertEqual(next(chunks), b"first")
            with self.refuses("timeout"):
                next(chunks)
        self.assertEqual(len(a.requests), 1)


if __name__ == "__main__":
    unittest.main()
