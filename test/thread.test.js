import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.GMAIL_TIDY_DIR = '/nonexistent-gmail-tidy-test';
const { trimQuoted, unsubscribeLinks, buildDraft } = await import('../src/gmail.js');
const { auditEntry } = await import('../src/audit.js');
const { _TOOLS, _call } = await import('../src/server.js');

test('trims the quoted history a reply repeats, in English and Spanish', () => {
  const en = 'Sounds good, Tuesday works.\n\nOn Mon, Oct 20, 2026 at 9:12 AM Ana <ana@example.com> wrote:\n> Can we meet Tuesday?\n> Thanks';
  assert.equal(trimQuoted(en), 'Sounds good, Tuesday works.');
  const es = 'Dale, el martes me acomoda.\n\nEl lun, 20 oct 2026 a las 9:12, Ana (<ana@example.com>) escribió:\n\n> ¿Nos juntamos el martes?';
  assert.equal(trimQuoted(es), 'Dale, el martes me acomoda.');
});

test('keeps a message that quotes nothing, and drops stray quoted lines', () => {
  assert.equal(trimQuoted('Hola,\n\nAdjunto la factura.\n\nSaludos'), 'Hola,\n\nAdjunto la factura.\n\nSaludos');
  assert.equal(trimQuoted('Respuesta\n> línea citada suelta\nFin'), 'Respuesta\nFin');
  // "wrote:" inside normal prose, with no quoted lines after it, is not a cut point.
  assert.equal(trimQuoted('As the author wrote: the end is near.\nMore text here.'), 'As the author wrote: the end is near.\nMore text here.');
});

test('parses List-Unsubscribe into web and mail links', () => {
  assert.deepEqual(unsubscribeLinks('<mailto:leave@list.example>, <https://list.example/u/abc>'), { web: 'https://list.example/u/abc', mail: 'mailto:leave@list.example' });
  assert.deepEqual(unsubscribeLinks('<https://a.example/x>'), { web: 'https://a.example/x', mail: null });
  assert.deepEqual(unsubscribeLinks(''), { web: null, mail: null });
});

test('an edited draft keeps the thread headers it had', () => {
  const raw = buildDraft({ from: 'me@example.com', to: 'you@example.com', subject: 'Re: Hi', body: 'v2', inReplyTo: '<abc@x>', references: '<abc@x>' });
  assert.match(raw, /^In-Reply-To: <abc@x>$/m);
  assert.match(raw, /^References: <abc@x>$/m);
});

test('update_draft is audited without the new text', () => {
  const e = auditEntry('update_draft', { account: 'a@example.com', draft_id: 'r1', body: 'secret', attachments: ['/x/a.pdf'] });
  assert.deepEqual(e.args, { account: 'a@example.com', draft_id: 'r1', attachments: ['/x/a.pdf'], body_changed: true });
});

test('the new tools are read-only except update_draft, and none sends', () => {
  const byName = Object.fromEntries(_TOOLS.map((t) => [t.name, t]));
  for (const n of ['get_thread', 'search_all_accounts', 'newsletters', 'list_drafts']) assert.equal(byName[n].annotations.readOnlyHint, true, n);
  assert.equal(byName.update_draft.annotations.destructiveHint, false);
  assert.ok(!/unsubscribe/.test(Object.keys(byName).join(' ')), 'no tool unsubscribes on its own');
});

test('update_draft refuses a call that changes nothing', async () => {
  await assert.rejects(_call('update_draft', { account: 'x', draft_id: 'r1' }), /Nothing to change/);
  await assert.rejects(_call('update_draft', { account: 'x', draft_id: 'r1', keep_attachments: 'yes' }), /true or false/);
});
