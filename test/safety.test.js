// The promise of this project is "it can organize your mail but never send or delete it".
// These tests are what keep that promise honest.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';

process.env.GMAIL_TIDY_DIR = '/nonexistent-gmail-tidy-test';
const { _TOOLS } = await import('../src/server.js');
const { SCOPES } = await import('../src/auth.js');
const { assertSafeLabels, filterAction, relabel } = await import('../src/gmail.js');

test('the forbidden-name rule still catches real send tools', () => {
  const rule = /(^|_)(send|reply|forward|trash)(_|$)/;
  for (const bad of ['send_email', 'reply', 'forward_email', 'trash_thread', 'quick_reply']) assert.ok(rule.test(bad), bad);
  assert.ok(!rule.test('sender_stats'));
});

test('asks only for the scopes it needs', () => {
  assert.deepEqual([...SCOPES].sort(), [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.settings.basic',
  ]);
});

test('no tool sends, replies, forwards or deletes mail', () => {
  for (const t of _TOOLS) {
    // Whole words only: sender_stats counts senders, it doesn't send.
    assert.ok(!/(^|_)(send|reply|forward|trash)(_|$)/.test(t.name), `forbidden tool: ${t.name}`);
    if (t.name.includes('delete')) assert.equal(t.name, 'delete_filter');
  }
});

test('the code never calls a send, trash or delete endpoint', () => {
  const forbidden = [
    /messages\.send/, /drafts\.send/, /\.trash\(/, /messages\.delete/, /batchDelete/, /threads\.(trash|delete)/,
    /\[\s*['"`](send|trash|batchDelete)['"`]\s*\]/, // bracket access, e.g. messages['send']
    /forward(ing)?\s*:/, /setAutoForwarding|updateVacation|forwardingAddresses/,
  ];
  for (const folder of ['../src/', '../bin/']) {
    const dir = new URL(folder, import.meta.url);
    for (const file of readdirSync(dir)) {
      // Comments may mention these names while explaining the rule; only code counts.
      const code = readFileSync(new URL(file, dir), 'utf8').replace(/^\s*\/\/.*$/gm, '');
      for (const pattern of forbidden) assert.ok(!pattern.test(code), `${folder}${file} matches ${pattern}`);
    }
  }
});

test('Trash and Spam can never be added, by name or ID, in any case', () => {
  for (const label of ['TRASH', 'trash', 'Spam', 'SPAM']) assert.throws(() => assertSafeLabels([label]), /not allowed/);
  assert.doesNotThrow(() => assertSafeLabels(['INBOX', 'Label_12']));
  assert.throws(() => relabel('x@example.com', { ids: ['1'], add: ['TRASH'] }), /not allowed/);
});

test('a filter action is only ever two label lists', () => {
  const action = filterAction({ add: ['Label_1'], remove: ['UNREAD'], forward: 'evil@example.com' });
  assert.deepEqual(Object.keys(action).sort(), ['addLabelIds', 'removeLabelIds']);
  assert.throws(() => filterAction({ add: ['TRASH'] }), /not allowed/);
  assert.throws(() => filterAction({}), /at least one label/);
});
