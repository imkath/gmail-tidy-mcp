// Exercises the real DPAPI path. Only meaningful on Windows, where CI runs it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('stores the key with DPAPI and reads it back', { skip: process.platform !== 'win32' }, async () => {
  process.env.GMAIL_TIDY_DIR = mkdtempSync(join(tmpdir(), 'gmail-tidy-win-'));
  delete process.env.GMAIL_TIDY_KEY;
  const store = await import('../src/store.js');
  store.saveAccount('a@example.com', { refresh_token: 'very-secret' }, 'x');
  const keyFile = join(process.env.GMAIL_TIDY_DIR, 'key.dpapi');
  assert.ok(existsSync(keyFile));
  assert.ok(!readFileSync(join(process.env.GMAIL_TIDY_DIR, 'tokens.enc'), 'utf8').includes('very-secret'));
  assert.equal(store.getTokens('a@example.com').refresh_token, 'very-secret');
});
