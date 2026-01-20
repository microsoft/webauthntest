import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const WORKER_NAME = process.env.CF_WORKER_NAME || process.env.CF_PAGES_PROJECT || 'webauthntest';
const D1_NAME = process.env.CF_D1_NAME || 'webauthntest';

const ROOT = process.cwd();

function toPlatformCommand(cmd, args) {
  if (process.platform !== 'win32') return { cmd, args };
  // On Windows, route through cmd.exe to reliably execute npm/npx and other .cmd shims.
  return { cmd: 'cmd.exe', args: ['/d', '/s', '/c', cmd, ...args] };
}

function log(msg) {
  process.stdout.write(`${msg}\n`);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function retry(label, fn, { attempts = 3, baseDelayMs = 1000 } = {}) {
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      const delay = baseDelayMs * Math.pow(2, i - 1);
      log(`  (${label} failed, retry ${i}/${attempts} in ${delay}ms)`);
      await sleep(delay);
    }
  }
  throw lastErr;
}

function run(cmd, args, { input, allowFailure = false } = {}) {
  return new Promise((resolve, reject) => {
    const platform = toPlatformCommand(cmd, args);
    const child = spawn(platform.cmd, platform.args, {
      cwd: ROOT,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => (stdout += d.toString()));
    child.stderr.on('data', (d) => (stderr += d.toString()));

    child.on('error', (err) => {
      if (allowFailure) return resolve({ code: 1, stdout, stderr: `${stderr}\n${String(err)}`.trim() });
      reject(err);
    });

    if (typeof input === 'string') {
      child.stdin.write(input);
    }
    child.stdin.end();

    child.on('close', (code) => {
      if (code !== 0 && !allowFailure) {
        const e = new Error(`Command failed (${code}): ${cmd} ${args.join(' ')}`);
        e.stdout = stdout;
        e.stderr = stderr;
        return reject(e);
      }
      resolve({ code: code ?? 0, stdout, stderr });
    });
  });
}

async function runWrangler(args, opts = {}) {
  // Always use npx so a fresh clone works without global installs.
  return run('npx', ['--yes', 'wrangler@4', ...args], opts);
}

function extractUuid(text) {
  const m = String(text).match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  return m ? m[0] : null;
}

function randomSecret() {
  // URL-safe base64 without padding
  return crypto.randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function ensureNpmInstall() {
  log('• Installing dependencies (npm)…');
  const lock = await fs
    .access(path.join(ROOT, 'package-lock.json'))
    .then(() => true)
    .catch(() => false);

  if (lock) {
    const ci = await run('npm', ['ci'], { allowFailure: true });
    if (ci.code === 0) return;
    log('  (npm ci failed; falling back to npm install)');
    await run('npm', ['install'], { allowFailure: false });
    return;
  }

  await run('npm', ['install'], { allowFailure: false });
}

async function ensureWranglerAuth() {
  log('• Checking Cloudflare auth…');
  const who = await runWrangler(['whoami'], { allowFailure: true });
  if (who.code === 0) return;

  log('• Not logged in. Starting `wrangler login` (browser may open)…');
  await runWrangler(['login'], { allowFailure: false });
}

async function ensureD1Database() {
  log(`• Ensuring D1 database exists (${D1_NAME})…`);

  const res = await retry(
    'd1 ensure',
    async () => {
      const create = await runWrangler(['d1', 'create', D1_NAME], { allowFailure: true });
      let uuid = extractUuid(create.stdout) || extractUuid(create.stderr);
      if (uuid) return { uuid, create };

      const info = await runWrangler(['d1', 'info', D1_NAME], { allowFailure: true });
      uuid = extractUuid(info.stdout) || extractUuid(info.stderr);
      if (uuid) return { uuid, create };

      throw new Error('Unable to discover D1 database UUID');
    },
    { attempts: 3, baseDelayMs: 1000 }
  );

  let uuid = res.uuid;

  if (!uuid) {
    throw new Error(
      `Could not determine D1 database_id for ${D1_NAME}.\n` +
        `Create output:\n${res.create?.stdout || ''}\n${res.create?.stderr || ''}`
    );
  }

  log(`  D1 database_id: ${uuid}`);
  return uuid;
}

async function patchWranglerToml(databaseId) {
  const file = path.join(ROOT, 'wrangler.toml');
  log('• Updating wrangler.toml D1 database_id…');
  const raw = await fs.readFile(file, 'utf8');

  let next = raw;
  if (next.includes('database_id = "REPLACE_ME"')) {
    next = next.replace('database_id = "REPLACE_ME"', `database_id = "${databaseId}"`);
  } else {
    // Replace any existing database_id line inside the D1 block.
    next = next.replace(/database_id\s*=\s*"[^"]*"/g, `database_id = "${databaseId}"`);
  }

  if (next !== raw) {
    await fs.writeFile(file, next, 'utf8');
  }
}

async function applySchemaRemote() {
  log('• Applying D1 schema (remote)…');
  await runWrangler(['d1', 'execute', D1_NAME, '--file=./schema.sql', '--remote']);
}

async function ensureSecret() {
  const secret = process.env.CHALLENGE_HMAC_SECRET || randomSecret();

  log('• Setting Worker secret CHALLENGE_HMAC_SECRET…');
  // wrangler secret put reads the value from stdin.
  await runWrangler(['secret', 'put', 'CHALLENGE_HMAC_SECRET', '--name', WORKER_NAME], { input: `${secret}\n` });

  if (!process.env.CHALLENGE_HMAC_SECRET) {
    log('  Generated CHALLENGE_HMAC_SECRET (saved only in Cloudflare).');
  }
}

async function ensureUidHashSecret() {
  // IMPORTANT: UID_HASH_SECRET affects how UIDs are derived.
  // Overwriting it would effectively "move" users and break existing credentials.
  // So: only set it if explicitly provided OR if it does not exist yet.

  const provided = process.env.UID_HASH_SECRET;
  if (provided) {
    log('• Setting Worker secret UID_HASH_SECRET (from env)…');
    await runWrangler(['secret', 'put', 'UID_HASH_SECRET', '--name', WORKER_NAME], { input: `${provided}\n` });
    return;
  }

  const list = await runWrangler(['secret', 'list', '--name', WORKER_NAME], { allowFailure: true });
  const existing = (list.stdout || '').toLowerCase().includes('"name": "uid_hash_secret"');
  if (existing) {
    log('• UID_HASH_SECRET already configured on Worker.');
    return;
  }

  const generated = randomSecret();
  log('• UID_HASH_SECRET not found; generating and setting Worker secret UID_HASH_SECRET…');
  await runWrangler(['secret', 'put', 'UID_HASH_SECRET', '--name', WORKER_NAME], { input: `${generated}\n` });
  log('  Generated UID_HASH_SECRET (saved only in Cloudflare).');
}

async function deploy() {
  log('• Deploying Worker…');
  const res = await runWrangler(['deploy', '--name', WORKER_NAME]);
  log(res.stdout.trim());
}

async function main() {
  const argv = new Set(process.argv.slice(2));
  if (argv.has('--help') || argv.has('-h')) {
    log('Usage: npm run bootstrap:cf');
    log('Environment: CF_WORKER_NAME, CF_D1_NAME, CHALLENGE_HMAC_SECRET, UID_HASH_SECRET');
    process.exit(0);
  }
  const dryRun = argv.has('--dry-run');

  log('Bootstrapping Cloudflare Workers (edge-native)…');

  await ensureNpmInstall();
  await ensureWranglerAuth();
  const dbId = await ensureD1Database();
  await patchWranglerToml(dbId);
  if (!dryRun) {
    await applySchemaRemote();
    await ensureSecret();
    await ensureUidHashSecret();
    await deploy();
  } else {
    log('• Dry run: skipped schema/secret/deploy');
  }

  log('Done.');
}

main().catch((err) => {
  console.error('\nBootstrap failed.');
  console.error(err?.message || err);
  if (err?.stdout) console.error('\nstdout:\n' + err.stdout);
  if (err?.stderr) console.error('\nstderr:\n' + err.stderr);
  process.exit(1);
});
