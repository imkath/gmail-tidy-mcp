// A local, append-only record of every change a tool made, so that if a malicious
// email ever steers the model, you can see exactly what happened and undo it.
// It records what changed, never message bodies, draft text or signatures.
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DIR } from './store.js';

export const AUDIT_FILE = join(DIR, 'audit.log');

// Fields worth keeping per tool. Anything not listed here is left out on purpose.
const KEEP = {
  organize_emails: ['account', 'message_ids', 'query', 'max', 'add_labels', 'remove_labels'],
  create_label: ['account', 'name'],
  update_label: ['account', 'label', 'new_name', 'background', 'sidebar', 'in_message_list'],
  create_filter: ['account', 'from', 'to', 'subject', 'query', 'add_labels', 'remove_labels', 'skip_inbox'],
  delete_filter: ['account', 'filter_id'],
  create_draft: ['account', 'to', 'cc', 'subject', 'reply_to_id'],
  set_signature: ['account', 'send_as'],
  get_attachment: ['account', 'message_id', 'attachment', 'allow_risky'],
  connect_account: ['email', 'label'],
  finish_connect_account: ['email'],
};

export function auditEntry(tool, args = {}, result = '', time = new Date()) {
  const kept = Object.fromEntries((KEEP[tool] ?? []).filter((k) => args[k] !== undefined).map((k) => [k, args[k]]));
  if (tool === 'set_signature') kept.signature_length = String(args.signature ?? '').length;
  if (tool === 'organize_emails' && Array.isArray(kept.message_ids) && kept.message_ids.length > 20) {
    kept.message_ids = `${kept.message_ids.length} ids`;
  }
  return { time: time.toISOString(), tool, args: kept, result: String(result).split('\n')[0].slice(0, 200) };
}

export function recordChange(tool, args, result) {
  if (!KEEP[tool]) return;
  // get_attachment only changes something when it writes a file.
  if (tool === 'get_attachment' && !/^(SECURITY NOTES[\s\S]*\n\n)?Saved /.test(result)) return;
  try {
    mkdirSync(DIR, { recursive: true, mode: 0o700 });
    const fresh = !existsSync(AUDIT_FILE);
    appendFileSync(AUDIT_FILE, JSON.stringify(auditEntry(tool, args, result.replace(/^SECURITY NOTES[\s\S]*?\n\n/, ''))) + '\n', { mode: 0o600 });
    if (fresh) chmodSync(AUDIT_FILE, 0o600);
  } catch {
    // The change already happened; failing to log it must not hide that from the user.
  }
}

export function recentChanges(limit = 20, account) {
  if (!existsSync(AUDIT_FILE)) return [];
  const rows = readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
  const mine = account ? rows.filter((r) => [r.args.account, r.args.email].includes(account)) : rows;
  return mine.slice(-Math.min(Math.max(Number(limit) || 20, 1), 500));
}
