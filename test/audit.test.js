import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.GMAIL_TIDY_DIR = mkdtempSync(join(tmpdir(), 'gmail-tidy-audit-'));
const { auditEntry, recordChange, recentChanges, AUDIT_FILE } = await import('../src/audit.js');

test('keeps what changed but never draft text or the signature itself', () => {
  const draft = auditEntry('create_draft', { account: 'a@example.com', to: 'b@example.com', subject: 'Hi', body: 'secret body' });
  assert.deepEqual(draft.args, { account: 'a@example.com', to: 'b@example.com', subject: 'Hi' });
  const sig = auditEntry('set_signature', { account: 'a@example.com', signature: 'Ana, CEO' });
  assert.deepEqual(sig.args, { account: 'a@example.com', signature_length: 8 });
});

test('records changes, skips reads, and the log is private', () => {
  recordChange('search_emails', { account: 'a@example.com', query: 'x' }, 'found');
  recordChange('organize_emails', { account: 'a@example.com', query: 'from:x', remove_labels: ['INBOX'] }, 'Done: applied the change to 3 emails');
  recordChange('get_attachment', { account: 'a@example.com', message_id: '1', attachment: '1' }, 'File: notes.txt ...');
  recordChange('get_attachment', { account: 'b@example.com', message_id: '2', attachment: '1' }, 'Saved factura.pdf to /tmp/x');
  const rows = recentChanges();
  assert.deepEqual(rows.map((r) => r.tool), ['organize_emails', 'get_attachment']);
  assert.deepEqual(recentChanges(20, 'b@example.com').map((r) => r.args.message_id), ['2']);
  assert.equal(statSync(AUDIT_FILE).mode & 0o777, 0o600);
  assert.ok(!readFileSync(AUDIT_FILE, 'utf8').includes('notes.txt'));
});
