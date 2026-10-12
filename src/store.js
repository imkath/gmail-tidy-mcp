// Account index and token storage.
//
// The index (email + label) is plain JSON: nothing in it is secret.
// Tokens are encrypted with AES-256-GCM. The key never touches the disk in clear:
//   macOS   -> login Keychain (`security`)
//   Linux   -> Secret Service via `secret-tool` (libsecret)
//   Windows -> a key file protected with DPAPI for the current user
// GMAIL_TIDY_KEY (64 hex chars) overrides all of the above, for headless setups.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync, renameSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DIR = process.env.GMAIL_TIDY_DIR ?? join(homedir(), '.config', 'gmail-tidy-mcp');
const INDEX = join(DIR, 'accounts.json');
const TOKENS = join(DIR, 'tokens.enc');
const SERVICE = 'gmail-tidy-mcp';
const KEY_NAME = 'token-key';

// Writes to a temp file and renames it, so a crash mid-write can't leave a
// truncated tokens.enc behind.
function writePrivate(path, data) {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  chmodSync(DIR, 0o700);
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

// A new key is only created when there is nothing encrypted yet. If tokens exist and
// the key can't be read (locked keyring, cancelled prompt...), failing loudly is far
// better than silently replacing the key and losing every account.
export function newKeyAllowed(where) {
  if (existsSync(TOKENS)) {
    throw new Error(
      `Could not read the encryption key from ${where}, and tokens already exist, so no new key was created. ` +
        'Unlock your keyring and try again.'
    );
  }
}

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'], ...opts }).trim();
}

function macKey() {
  const args = ['-s', SERVICE, '-a', KEY_NAME];
  try {
    return Buffer.from(run('security', ['find-generic-password', ...args, '-w']), 'hex');
  } catch {
    newKeyAllowed('the macOS Keychain');
    const key = randomBytes(32);
    // The key shows up in this process's arguments for an instant while it is created.
    // Reading it back later does not expose it.
    run('security', ['add-generic-password', ...args, '-w', key.toString('hex')]);
    return key;
  }
}

function linuxKey() {
  const attrs = ['service', SERVICE, 'account', KEY_NAME];
  try {
    const hex = run('secret-tool', ['lookup', ...attrs]);
    if (hex) return Buffer.from(hex, 'hex');
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(
        'secret-tool not found. Install libsecret-tools (or set GMAIL_TIDY_KEY) so tokens can be encrypted.'
      );
    }
  }
  newKeyAllowed('the Secret Service');
  const key = randomBytes(32);
  // secret-tool reads the secret from stdin, so it never appears in the process list.
  run('secret-tool', ['store', '--label=gmail-tidy-mcp token key', ...attrs], { input: key.toString('hex') });
  return key;
}

function windowsKey() {
  const file = join(DIR, 'key.dpapi');
  const dpapi = (op, data) =>
    run(
      'powershell',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        'Add-Type -AssemblyName System.Security;' +
          '$b=[Convert]::FromBase64String($env:GT_DATA);' +
          `$r=[Security.Cryptography.ProtectedData]::${op}($b,$null,'CurrentUser');` +
          '[Convert]::ToBase64String($r)',
      ],
      // Passed through the environment, not the command line.
      { env: { ...process.env, GT_DATA: data } }
    );
  if (existsSync(file)) return Buffer.from(dpapi('Unprotect', readFileSync(file, 'utf8').trim()), 'base64');
  newKeyAllowed('the DPAPI key file');
  const key = randomBytes(32);
  writePrivate(file, dpapi('Protect', key.toString('base64')));
  return key;
}

let cachedKey = null;
export function _setKeyForTests(key) {
  cachedKey = key;
}

function getKey() {
  if (cachedKey) return cachedKey;
  if (process.env.GMAIL_TIDY_KEY) {
    cachedKey = Buffer.from(process.env.GMAIL_TIDY_KEY, 'hex');
    delete process.env.GMAIL_TIDY_KEY; // don't hand it down to child processes
  }
  else if (process.platform === 'darwin') cachedKey = macKey();
  else if (process.platform === 'win32') cachedKey = windowsKey();
  else cachedKey = linuxKey();
  if (cachedKey.length !== 32) throw new Error('The encryption key must be 32 bytes (64 hex characters).');
  return cachedKey;
}

export function encrypt(obj, key = getKey()) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
}

export function decrypt(b64, key = getKey()) {
  const buf = Buffer.from(b64, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8'));
}

function readTokens() {
  if (!existsSync(TOKENS)) return {};
  try {
    return decrypt(readFileSync(TOKENS, 'utf8'));
  } catch {
    throw new Error(
      `Could not decrypt ${TOKENS}: the key does not match or the file is damaged. ` +
        'Remove the file and reconnect your accounts.'
    );
  }
}

export function listAccounts() {
  return existsSync(INDEX) ? JSON.parse(readFileSync(INDEX, 'utf8')) : [];
}

export function getTokens(email) {
  return readTokens()[email] ?? null;
}

export function saveAccount(email, tokens, label) {
  const all = readTokens();
  all[email] = { ...all[email], ...tokens };
  writePrivate(TOKENS, encrypt(all));
  const index = listAccounts().filter((a) => a.email !== email);
  index.push({ email, label: label ?? null });
  writePrivate(INDEX, JSON.stringify(index, null, 2));
}

export function updateTokens(email, tokens) {
  const all = readTokens();
  if (!all[email]) return;
  all[email] = { ...all[email], ...tokens };
  writePrivate(TOKENS, encrypt(all));
}

export function removeAccount(email) {
  const all = readTokens();
  delete all[email];
  writePrivate(TOKENS, encrypt(all));
  writePrivate(INDEX, JSON.stringify(listAccounts().filter((a) => a.email !== email), null, 2));
}

// Accepts the exact address or its label (case-insensitive).
export function resolveAccount(target) {
  if (!target) throw new Error('Missing account: pass an email address or its label (see list_accounts).');
  const accounts = listAccounts();
  const wanted = String(target).toLowerCase();
  const hit =
    accounts.find((a) => a.email.toLowerCase() === wanted) ??
    accounts.find((a) => a.label && a.label.toLowerCase() === wanted);
  if (!hit) throw new Error(`No account matches "${target}". Use list_accounts to see what is connected.`);
  return hit.email;
}
