// Start a fresh Node process with one synthetic local CA, preserving normal PKI
// verification. No NODE_TLS_REJECT_UNAUTHORIZED override, production call or key
// output. Private fixture files are removed when the test process terminates.
import { mkdtemp, writeFile, rm, readdir, chmod, readFile, realpath } from 'node:fs/promises';
import { execFileSync, spawn } from 'node:child_process';
import { resolve, join } from 'node:path';
const root = resolve('.');
const vitestEntry = resolve(process.env.SDK_VITEST_ENTRY ?? join(root, 'js/node_modules/vitest/vitest.mjs'));
// Optional unpacked exact npm artifact. The test imports its dist runtime while
// fixture helpers remain in this checkout; dependencies may be reused read-only.
if (process.argv.length !== 2 && (process.argv.length !== 4 || process.argv[2] !== '--package-root')) throw new Error('Expected --package-root <unpacked artifact>');
let packageRoot;
if (process.argv[3]) {
  packageRoot = await realpath(resolve(process.argv[3]));
  const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  if (metadata.name !== '@anonrouter/confidential' || metadata.version !== '0.1.3') throw new Error('Unexpected confidential artifact identity');
  for (const name of ['client.js', 'gateway/connection-session.js', 'gateway/transport-node.js', 'gateway/retained-operation-node.js']) await readFile(join(packageRoot, 'dist', name));
}
const fixture = await mkdtemp(join(root, '.bound-client-tls-'));
const openssl = args => execFileSync('openssl', args, { cwd: fixture, stdio: 'ignore' });
try {
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=SDK bound-client local CA', '-days', '1']);
  for (const slot of ['a', 'b']) {
    openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${slot}.key`, '-out', `${slot}.csr`, '-subj', `/CN=${slot}`]);
    await writeFile(join(fixture, `${slot}.ext`), 'subjectAltName=IP:127.0.0.1,DNS:localhost\n', { mode: 0o600 });
    openssl(['x509', '-req', '-in', `${slot}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${slot}.pem`, '-days', '1', '-extfile', `${slot}.ext`]);
  }
  for (const file of await readdir(fixture)) await chmod(join(fixture, file), 0o600);
  const child = spawn(process.execPath, [
    vitestEntry,
    'run', 'test/gateway-bound-client.test.ts', '--maxWorkers=1', '--config', join(root, 'js/confidential/vitest.bound.config.ts'),
  ], { cwd: join(root, 'js/confidential'), stdio: 'inherit', env: {
    ...process.env, ...(packageRoot ? { SDK_BOUND_CLIENT_PACKAGE_ROOT: packageRoot } : { SDK_BOUND_CLIENT_PACKAGE_ROOT: '' }), NODE_EXTRA_CA_CERTS: join(fixture, 'ca.pem'), SDK_BOUND_CLIENT_FIXTURE: fixture,
  } });
  const exit = await new Promise(resolve => { child.once('exit', code => resolve(code ?? 1)); child.once('error', () => resolve(1)); });
  process.exitCode = exit;
} finally { await rm(fixture, { recursive: true, force: true }); }
