// The sign-in flow, minus Google: the loopback server and the post-login checks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

process.env.GMAIL_TIDY_DIR = '/nonexistent-gmail-tidy-test';
const { waitForCode, checkGrant, SCOPES } = await import('../src/auth.js');

async function loopback() {
  const server = createServer();
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test('accepts the code when the state matches', async () => {
  const { server, base } = await loopback();
  const code = waitForCode(server, 'good-state', 5000);
  const res = await fetch(`${base}/?state=good-state&code=abc`);
  assert.equal(res.status, 200);
  assert.equal(await code, 'abc');
});

test('a forged state gets a 400 and does not abort the sign-in', async () => {
  const { server, base } = await loopback();
  const code = waitForCode(server, 'good-state', 5000);
  assert.equal((await fetch(`${base}/?state=forged&code=evil`)).status, 400);
  await fetch(`${base}/?state=good-state&code=real`);
  assert.equal(await code, 'real');
});

test('surfaces errors returned by Google', async () => {
  const { server, base } = await loopback();
  const rejected = assert.rejects(waitForCode(server, 's', 5000), /access_denied/);
  await fetch(`${base}/?state=s&error=access_denied`);
  await rejected;
});

test('ignores unrelated requests such as /favicon.ico', async () => {
  const { server, base } = await loopback();
  const code = waitForCode(server, 's', 5000);
  assert.equal((await fetch(`${base}/favicon.ico`)).status, 404);
  await fetch(`${base}/?state=s&code=xyz`);
  assert.equal(await code, 'xyz');
});

test('times out if the user never finishes', async () => {
  const { server } = await loopback();
  await assert.rejects(waitForCode(server, 's', 50), /timed out/);
});

test('refuses and revokes when a different account signs in', async () => {
  let revoked = false;
  await assert.rejects(
    checkGrant({
      requested: 'me@example.com',
      signedIn: 'someone@example.com',
      tokens: { scope: SCOPES.join(' ') },
      revoke: async () => { revoked = true; },
    }),
    /signed in as someone@example.com/
  );
  assert.ok(revoked);
});

test('refuses unexpected scopes', async () => {
  await assert.rejects(
    checkGrant({
      requested: 'me@example.com',
      signedIn: 'me@example.com',
      tokens: { scope: [...SCOPES, 'https://mail.google.com/'].join(' ') },
      revoke: async () => {},
    }),
    /unexpected scopes/
  );
});

test('accepts the right account with the right scopes, in any order', async () => {
  const tokens = { scope: [...SCOPES].reverse().join(' ') };
  const out = await checkGrant({ requested: 'Me@Example.com', signedIn: 'me@example.com', tokens, revoke: async () => {} });
  assert.deepEqual(out, { email: 'me@example.com', tokens });
});

test('refuses missing scopes, including a token with no scope at all', async () => {
  for (const scope of [undefined, SCOPES[0]]) {
    let revoked = false;
    await assert.rejects(
      checkGrant({ requested: 'me@example.com', signedIn: 'me@example.com', tokens: { scope }, revoke: async () => { revoked = true; } }),
      /not granted/
    );
    assert.ok(revoked);
  }
});

test('refuses and revokes when no account was requested', async () => {
  let revoked = false;
  await assert.rejects(
    checkGrant({ requested: undefined, signedIn: 'me@example.com', tokens: { scope: SCOPES.join(' ') }, revoke: async () => { revoked = true; } }),
    /No account/
  );
  assert.ok(revoked);
});
