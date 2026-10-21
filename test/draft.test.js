import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.GMAIL_TIDY_DIR = '/nonexistent-gmail-tidy-test';
const { buildDraft, encodeAddresses } = await import('../src/gmail.js');
const base = { from: 'me@example.com', to: 'you@example.com', subject: 'Hi', body: 'Hello' };

test('refuses line breaks in any header (no hidden Bcc)', () => {
  assert.throws(() => buildDraft({ ...base, to: 'a@x.com\r\nBcc: evil@x.com' }), /line breaks/);
  assert.throws(() => buildDraft({ ...base, cc: 'a@x.com\nBcc: evil@x.com' }), /line breaks/);
  assert.throws(() => buildDraft({ ...base, subject: 'Hi\r\n\r\nnew body' }), /line breaks/);
  assert.throws(() => buildDraft({ ...base, inReplyTo: '<id>\r\nBcc: evil@x.com' }), /line breaks/);
});

test('needs a recipient', () => {
  assert.throws(() => buildDraft({ ...base, to: undefined }), /recipient/);
});

test('encodes non-ASCII subjects and names, and keeps encoded words short', () => {
  const raw = buildDraft({ ...base, to: 'José Pérez <jose@example.com>', subject: 'Reunión de mañana con el equipo de diseño y producto' });
  assert.match(raw, /^To: =\?UTF-8\?B\?[^?]+\?= <jose@example\.com>$/m);
  for (const word of raw.match(/=\?UTF-8\?B\?[^?]*\?=/g)) assert.ok(word.length <= 75, word);
  assert.ok(!/[^\x00-\x7f]/.test(raw.split('\r\n\r\n')[0]), 'headers must be ASCII');
});

test('omits empty optional headers', () => {
  const raw = buildDraft({ ...base, subject: undefined });
  assert.ok(!raw.includes('Subject:'));
  assert.ok(!raw.includes('In-Reply-To:'));
  assert.ok(raw.includes('Content-Transfer-Encoding: 8bit'));
});

test('quotes plain display names and leaves bare addresses alone', () => {
  assert.equal(encodeAddresses('Ana <ana@x.com>, bob@y.com'), '"Ana" <ana@x.com>, bob@y.com');
});

test('a draft with attachments is multipart and keeps the text intact', () => {
  const raw = buildDraft({
    ...base, body: 'Adjunto la cotización.\nSaludos', boundary: 'B1',
    attachments: [{ filename: 'Cotización final.pdf', mimeType: 'application/pdf', bytes: Buffer.from('%PDF-1.7 test') }],
  });
  assert.match(raw, /^Content-Type: multipart\/mixed; boundary="B1"$/m);
  assert.match(raw, /--B1\r\nContent-Type: text\/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nAdjunto la cotización\.\r\nSaludos/);
  const word = `=?UTF-8?B?${Buffer.from('Cotización final.pdf').toString('base64')}?=`;
  assert.ok(raw.includes(`filename="${word}"; filename*=UTF-8''Cotizaci%C3%B3n%20final.pdf`));
  assert.ok(raw.includes(Buffer.from('%PDF-1.7 test').toString('base64')));
  assert.ok(raw.trimEnd().endsWith('--B1--'));
  assert.ok(!/[^\x00-\x7f]/.test(raw.split('\r\n\r\n')[0]), 'headers must be ASCII');
});

test('an attachment name cannot smuggle headers', () => {
  assert.throws(() => buildDraft({ ...base, attachments: [{ filename: 'a.pdf\r\nBcc: evil@x.com', bytes: Buffer.from('x') }] }), /line breaks/);
});
