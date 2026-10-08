// Compile the current retained transport and synthetic evidence helpers before
// loopback-only TLS tests. All generated files belong to this invocation.
import { mkdir, mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { execFileSync, spawn } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv.length !== 2) throw new Error('This runner accepts no arguments');
const parent = join(root, '.agent/connection-binding');
await mkdir(parent, { recursive: true, mode: 0o700 });
const build = await mkdtemp(join(parent, 'retained-tests-'));
try {
  const source = join(root, 'js/confidential');
  execFileSync(process.execPath, [join(root, 'js/node_modules/typescript/bin/tsc'),
    '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext',
    '--lib', 'ES2022,DOM', '--strict', '--esModuleInterop', '--skipLibCheck', '--resolveJsonModule',
    '--types', 'node', '--typeRoots', join(root, 'js/node_modules/@types'),
    '--rootDir', source, '--outDir', build,
    join(source, 'src/gateway/retained-operation-node.ts'),
    join(source, 'test/helpers/gateway-fixtures.ts')], { cwd: root, stdio: 'inherit' });
  await writeFile(join(build, 'package.json'), '{"type":"module"}\n', { mode: 0o600 });
  await symlink(join(root, 'js/node_modules'), join(build, 'node_modules'));
  const child = spawn(process.execPath, ['--test', join(root, 'acceptance/retained-operation-node.test.mjs')], {
    cwd: root, stdio: 'inherit', env: { ...process.env, SDK_RETAINED_TEST_BUILD: build },
  });
  process.exitCode = await new Promise(resolveExit => {
    child.once('exit', code => resolveExit(code ?? 1));
    child.once('error', () => resolveExit(1));
  });
} finally { await rm(build, { recursive: true, force: true }); }
