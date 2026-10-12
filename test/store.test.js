import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

process.env.GMAIL_TIDY_DIR = mkdtempSync(join(tmpdir(), 'gmail-tidy-'));
const store = await import('../src/store.js');
store._setKeyForTests(randomBytes(32));

test('tokens are encrypted on disk, owner-only, and round-trip', () => {
  store.saveAccount('a@example.com', { refresh_token: 'very-secret' }, 'personal');
  const file = join(process.env.GMAIL_TIDY_DIR, 'tokens.enc');
  assert.ok(!readFileSync(file, 'utf8').includes('very-secret'));
  if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(store.getTokens('a@example.com').refresh_token, 'very-secret');
});

test('a different key cannot decrypt (GCM authenticates)', () => {
  const blob = store.encrypt({ x: 1 }, randomBytes(32));
  assert.throws(() => store.decrypt(blob, randomBytes(32)));
});

test('accounts resolve by address or label, and unknown ones fail', () => {
  assert.equal(store.resolveAccount('PERSONAL'), 'a@example.com');
  assert.equal(store.resolveAccount('a@example.com'), 'a@example.com');
  assert.throws(() => store.resolveAccount('someone-else'));
  store.removeAccount('a@example.com');
  assert.equal(store.getTokens('a@example.com'), null);
});

test('never replaces the key once tokens exist', () => {
  // getKey only mints a key through newKeyAllowed. With tokens on disk it must refuse,
  // because a new key would make every stored account unreadable.
  store.saveAccount('c@example.com', { refresh_token: 'r' });
  assert.throws(() => store.newKeyAllowed('the keyring'), /no new key was created/);
});

test('token refresh keeps the refresh token', () => {
  store.saveAccount('b@example.com', { refresh_token: 'r1', access_token: 'a1' });
  store.updateTokens('b@example.com', { access_token: 'a2' });
  assert.deepEqual(store.getTokens('b@example.com'), { refresh_token: 'r1', access_token: 'a2' });
});
