import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Agent, request } from 'node:https';
import { createServer as createTcpServer } from 'node:net';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { resolve, join } from 'node:path';
import { createSpkiBoundGatewayTransport, BoundGatewayTransportError } from '../.transport-build/transport-node.js';

const liveServers = new Set();
let fixtureDirectory, ca, certificates;
const pin = cert => createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
const rejection = code => error => error instanceof BoundGatewayTransportError && error.code === code;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

before(async () => {
  fixtureDirectory = await mkdtemp(resolve('.synthetic-tls-'));
  const openssl = args => execFileSync('openssl', args, { cwd: fixtureDirectory, stdio: 'ignore' });
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=SDK local transport test CA', '-days', '1']);
  ca = await readFile(join(fixtureDirectory, 'ca.pem'), 'utf8');
  certificates = {};
  for (const name of ['a', 'b', 'wrong-host']) {
    openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`]);
    await writeFile(join(fixtureDirectory, `${name}.ext`), `subjectAltName=${name === 'wrong-host' ? 'DNS:wrong.example' : 'IP:127.0.0.1,DNS:localhost'}\n`, { mode: 0o600 });
    openssl(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.pem`, '-days', '1', '-extfile', `${name}.ext`]);
    certificates[name] = { cert: await readFile(join(fixtureDirectory, `${name}.pem`)), key: await readFile(join(fixtureDirectory, `${name}.key`)) };
  }
});

after(async () => {
  for (const server of liveServers) {
    server.closeAllConnections?.();
    for (const socket of server.testSockets ?? []) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
  await rm(fixtureDirectory, { recursive: true, force: true });
});

async function server(name, handler) {
  const observations = { httpBytes: 0, requests: 0, bodies: [], sockets: 0 };
  const instance = createServer(certificates[name], async (req, res) => {
    observations.requests++;
    let body = '';
    for await (const chunk of req) body += chunk;
    observations.bodies.push(body);
    if (handler) return handler(req, res);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ slot: name }));
  });
  instance.testSockets = new Set();
  instance.on('secureConnection', socket => {
    observations.sockets++;
    instance.testSockets.add(socket);
    socket.on('data', bytes => { observations.httpBytes += bytes.length; });
    socket.once('close', () => instance.testSockets.delete(socket));
  });
  instance.on('tlsClientError', () => {});
  await new Promise(resolve => instance.listen(0, '127.0.0.1', resolve));
  liveServers.add(instance);
  return { instance, observations, origin: `https://127.0.0.1:${instance.address().port}`, pin: pin(certificates[name].cert) };
}

function transport(target, overrides = {}) {
  return createSpkiBoundGatewayTransport({ origin: target.origin, expectedTlsSpkiSha256: target.pin, ca, ...overrides });
}

test('A evidence pin refuses B before B receives any HTTP headers or body', async () => {
  const b = await server('b');
  const bound = transport(b, { expectedTlsSpkiSha256: pin(certificates.a.cert) });
  try {
    await assert.rejects(bound.fetch(`${b.origin}/inference`, { method: 'POST', headers: { 'x-test-ticket': 'synthetic-only' }, body: 'synthetic-content' }), error => rejection('tls_pin_mismatch')(error) && error.dispatchPhase === 'before_http');
    await pause(25);
    assert.equal(b.observations.httpBytes, 0);
    assert.equal(b.observations.requests, 0);
    assert.deepEqual(b.observations.bodies, []);
  } finally { bound.close(); }
});

test('correct B pin succeeds under normal certificate and hostname validation', async () => {
  const b = await server('b');
  const bound = transport(b);
  try {
    const response = await bound.fetch(`${b.origin}/inference`, { method: 'POST', body: 'synthetic-b-body', credentials: 'omit' });
    assert.deepEqual(await response.json(), { slot: 'b' });
    assert.equal(b.observations.requests, 1);
    assert.deepEqual(b.observations.bodies, ['synthetic-b-body']);
  } finally { bound.close(); }
});

test('matching pin cannot bypass a hostname mismatch', async () => {
  const target = await server('wrong-host');
  const bound = transport(target);
  try {
    await assert.rejects(bound.fetch(`${target.origin}/inference`, { method: 'POST', body: 'must-not-arrive' }), rejection('tls_certificate'));
    assert.equal(target.observations.httpBytes, 0);
    assert.equal(target.observations.requests, 0);
  } finally { bound.close(); }
});

test('matching pin cannot bypass an untrusted certificate chain', async () => {
  const b = await server('b');
  const bound = transport(b, { ca: undefined });
  try {
    await assert.rejects(bound.fetch(`${b.origin}/inference`, { method: 'POST', body: 'must-not-arrive' }), rejection('tls_certificate'));
    assert.equal(b.observations.httpBytes, 0);
    assert.equal(b.observations.requests, 0);
  } finally { bound.close(); }
});

test('concurrent A and B transports and requests have isolated pins and pools', async () => {
  const a = await server('a');
  const b = await server('b');
  const boundA = transport(a), boundB = transport(b);
  try {
    const results = await Promise.all(Array.from({ length: 12 }, async (_, index) => {
      const target = index % 2 ? a : b;
      const response = await (index % 2 ? boundA : boundB).fetch(`${target.origin}/request`, { method: 'POST', body: `synthetic-${index}` });
      return (await response.json()).slot;
    }));
    assert.deepEqual(results, Array.from({ length: 12 }, (_, index) => index % 2 ? 'a' : 'b'));
    assert.equal(a.observations.requests, 6);
    assert.equal(b.observations.requests, 6);
    assert.equal(a.observations.sockets, 6);
    assert.equal(b.observations.sockets, 6);
  } finally { boundA.close(); boundB.close(); }
});

test('an already established ordinary keep-alive pool cannot bypass the A pin', async () => {
  const b = await server('b');
  const ordinary = new Agent({ ca, keepAlive: true });
  await new Promise((resolve, reject) => {
    const req = request(`${b.origin}/ordinary`, { agent: ordinary }, response => { response.resume(); response.once('end', resolve); });
    req.once('error', reject); req.end();
  });
  const bytesBefore = b.observations.httpBytes;
  const bound = transport(b, { expectedTlsSpkiSha256: pin(certificates.a.cert) });
  try {
    await assert.rejects(bound.fetch(`${b.origin}/bound`, { method: 'POST', body: 'must-not-arrive' }), rejection('tls_pin_mismatch'));
    await pause(25);
    assert.equal(b.observations.requests, 1);
    assert.equal(b.observations.httpBytes, bytesBefore);
  } finally { ordinary.destroy(); bound.close(); }
});

test('redirects are refused and never contacted', async () => {
  const destination = await server('b');
  const source = await server('a', (_req, res) => { res.writeHead(307, { location: `${destination.origin}/redirect-target` }); res.end(); });
  const bound = transport(source);
  try {
    await assert.rejects(bound.fetch(`${source.origin}/redirect`, { method: 'POST', body: 'synthetic' }), rejection('redirect'));
    assert.equal(destination.observations.requests, 0);
    assert.equal(destination.observations.httpBytes, 0);
  } finally { bound.close(); }
});

test('origin escape and unsafe agent, dispatcher, host and redirect overrides refuse before network', async () => {
  const a = await server('a'), b = await server('b');
  const bound = transport(a);
  try {
    await assert.rejects(bound.fetch(`${b.origin}/escape`), rejection('configuration'));
    for (const init of [{ agent: new Agent() }, { dispatcher: {} }, { redirect: 'follow' }, { credentials: 'include' }, { headers: { host: 'wrong.example' } }, { headers: { 'transfer-encoding': 'chunked' } }]) {
      await assert.rejects(bound.fetch(`${a.origin}/request`, init), rejection('configuration'));
      init.agent?.destroy();
    }
    assert.equal(a.observations.httpBytes, 0);
    assert.equal(b.observations.httpBytes, 0);
  } finally { bound.close(); }
});

test('origin and fingerprint must be runtime strings without implicit coercion', () => {
  assert.throws(() => createSpkiBoundGatewayTransport({ origin: new URL('https://example.com'), expectedTlsSpkiSha256: 'a'.repeat(64) }), rejection('configuration'));
  assert.throws(() => createSpkiBoundGatewayTransport({ origin: 'https://example.com', expectedTlsSpkiSha256: BigInt('1'.repeat(64)) }), rejection('configuration'));
});

test('streaming response finishes normally over the verified connection', async () => {
  const a = await server('a', async (_req, res) => {
    res.setHeader('content-type', 'text/event-stream');
    res.write('data: started\n\n');
    await pause(30);
    res.write('data: continued\n\n');
    await pause(30);
    res.end('data: [DONE]\n\n');
  });
  const bound = transport(a);
  try {
    const response = await bound.fetch(`${a.origin}/stream`);
    const reader = response.body.getReader();
    const first = await reader.read();
    assert.match(new TextDecoder().decode(first.value), /started/);
    let result = '';
    for (;;) { const chunk = await reader.read(); if (chunk.done) break; result += new TextDecoder().decode(chunk.value); }
    assert.match(result, /continued/);
    assert.match(result, /\[DONE\]/);
    assert.equal(a.observations.requests, 1);
  } finally { bound.close(); }
});

test('abort remains effective after response headers without replay', async () => {
  const a = await server('a', (_req, res) => { res.write('first'); });
  const bound = transport(a);
  const controller = new AbortController();
  try {
    const response = await bound.fetch(`${a.origin}/stream`, { signal: controller.signal });
    const reader = response.body.getReader();
    assert.equal((await reader.read()).done, false);
    controller.abort();
    await assert.rejects(reader.read());
    await pause(25);
    assert.equal(a.observations.requests, 1);
    assert.equal(a.instance.testSockets.size, 0);
  } finally { bound.close(); }
});

test('body cancellation closes the socket and transport close refuses reuse', async () => {
  const a = await server('a', (_req, res) => { res.write('first'); });
  const bound = transport(a);
  const response = await bound.fetch(`${a.origin}/stream`);
  const reader = response.body.getReader();
  await reader.read();
  await reader.cancel();
  await pause(25);
  assert.equal(a.instance.testSockets.size, 0);
  bound.close();
  await assert.rejects(bound.fetch(`${a.origin}/second`), rejection('cancelled'));
  assert.equal(a.observations.requests, 1);
});

test('already cancelled request writes nothing', async () => {
  const a = await server('a');
  const bound = transport(a);
  const controller = new AbortController(); controller.abort();
  try {
    await assert.rejects(bound.fetch(`${a.origin}/request`, { method: 'POST', body: 'must-not-arrive', signal: controller.signal }), rejection('cancelled'));
    assert.equal(a.observations.httpBytes, 0);
  } finally { bound.close(); }
});

test('abort during an unfinished TLS handshake releases the unowned socket', async () => {
  const sockets = new Set();
  const stalled = createTcpServer(socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('data', () => {}); });
  stalled.testSockets = sockets;
  await new Promise(resolve => stalled.listen(0, '127.0.0.1', resolve));
  liveServers.add(stalled);
  const bound = createSpkiBoundGatewayTransport({ origin: `https://127.0.0.1:${stalled.address().port}`, expectedTlsSpkiSha256: pin(certificates.a.cert), ca });
  const controller = new AbortController();
  try {
    const result = bound.fetch(`https://127.0.0.1:${stalled.address().port}/request`, { method: 'POST', body: 'must-not-arrive', signal: controller.signal });
    await pause(30);
    assert.equal(sockets.size, 1);
    controller.abort();
    await assert.rejects(result, rejection('cancelled'));
    await pause(30);
    assert.equal(sockets.size, 0);
  } finally { bound.close(); }
});

test('request deadline covers the response stream, closes its socket and never retries', async () => {
  const a = await server('a', (_req, res) => { res.write('first'); });
  const bound = transport(a, { requestTimeoutMs: 60 });
  try {
    const response = await bound.fetch(`${a.origin}/stream`);
    const reader = response.body.getReader();
    await reader.read();
    await assert.rejects(reader.read());
    await pause(25);
    assert.equal(a.observations.requests, 1);
    assert.equal(a.instance.testSockets.size, 0);
  } finally { bound.close(); }
});


test('approval expiring during TLS refuses all HTTP bytes before socket dispatch', async () => {
  const b = await server('b');
  const bound = transport(b, { beforeHttpDispatch() { throw new Error('synthetic approval expired'); } });
  try {
    await assert.rejects(bound.fetch(`${b.origin}/inference`, { method: 'POST', body: 'must-not-arrive' }),
      error => rejection('authorization')(error) && error.dispatchPhase === 'before_http');
    await pause(25);
    assert.equal(b.observations.httpBytes, 0);
    assert.equal(b.observations.requests, 0);
  } finally { bound.close(); }
});
