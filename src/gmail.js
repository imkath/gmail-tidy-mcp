// Read and organize: search, read, label, archive, filters and drafts.
// Never send and never delete. test/safety.test.js scans the code and fails if a
// send, trash or delete call shows up, and the label checks below keep mail out of
// Trash and Spam even if a caller asks for it.
import { google } from 'googleapis';
import { authedClient, isTokenError } from './auth.js';

const MAX_BODY = 40_000;
const FORBIDDEN_LABELS = new Set(['TRASH', 'SPAM']);

function api(email) {
  return google.gmail({ version: 'v1', auth: authedClient(email) });
}

async function run(email, fn) {
  try {
    return await fn(api(email));
  } catch (err) {
    if (isTokenError(err)) throw new Error(`Access to ${email} expired or was revoked. Reconnect it with connect_account.`);
    throw err;
  }
}

// Header values from Gmail are third-party text. Control characters are removed so a
// crafted subject can't fake extra lines (like "Labels:") in what the model reads.
export function header(headers, name) {
  const value = headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
}

function charsetOf(part) {
  const type = part.headers?.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? '';
  return type.match(/charset="?([\w-]+)"?/i)?.[1] ?? 'utf-8';
}

function decode(part) {
  const bytes = Buffer.from(part.body.data, 'base64url');
  try {
    return new TextDecoder(charsetOf(part), { fatal: false }).decode(bytes);
  } catch {
    return bytes.toString('utf8'); // unknown charset label
  }
}

// HTML is only a fallback. Tags, styles and scripts are stripped so hidden text
// (a classic prompt injection trick) and markup don't reach the model.
export function htmlToText(html) {
  return html
    .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<(\w+)[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>|<\/(p|div|li|tr|h\d)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n\n')
    .trim();
}

export function extractBody(payload) {
  if (!payload) return '';
  if (payload.mimeType === 'text/plain' && payload.body?.data) return decode(payload);
  let html = '';
  for (const part of payload.parts ?? []) {
    const text = extractBody(part);
    if (text && part.mimeType !== 'text/html') return text;
    if (part.mimeType === 'text/html' && part.body?.data) html ||= decode(part);
  }
  if (html) return htmlToText(html);
  if (!payload.body?.data) return '';
  return payload.mimeType === 'text/html' ? htmlToText(decode(payload)) : decode(payload);
}

export function search(email, query, maxResults = 10) {
  const n = Math.min(Math.max(Number(maxResults) || 10, 1), 50);
  return run(email, async (g) => {
    const { data } = await g.users.messages.list({ userId: 'me', q: query, maxResults: n });
    return Promise.all(
      (data.messages ?? []).map(async ({ id }) => {
        const { data: m } = await g.users.messages.get({
          userId: 'me',
          id,
          format: 'metadata',
          metadataHeaders: ['From', 'To', 'Subject', 'Date'],
        });
        const h = m.payload?.headers;
        return {
          id: m.id,
          from: header(h, 'From'),
          subject: header(h, 'Subject'),
          date: header(h, 'Date'),
          snippet: (m.snippet ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' '),
          labels: m.labelIds ?? [],
        };
      })
    );
  });
}

export function getMessage(email, id) {
  return run(email, async (g) => {
    const { data: m } = await g.users.messages.get({ userId: 'me', id, format: 'full' });
    const h = m.payload?.headers;
    let body = extractBody(m.payload);
    if (body.length > MAX_BODY) body = body.slice(0, MAX_BODY) + '\n[... body truncated ...]';
    return {
      from: header(h, 'From'),
      to: header(h, 'To'),
      cc: header(h, 'Cc'),
      subject: header(h, 'Subject'),
      date: header(h, 'Date'),
      labels: m.labelIds ?? [],
      body,
    };
  });
}

export function labels(email) {
  return run(email, async (g) => (await g.users.labels.list({ userId: 'me' })).data.labels ?? []);
}

export function profile(email) {
  return run(email, async (g) => (await g.users.getProfile({ userId: 'me' })).data);
}

export function createLabel(email, name) {
  return run(email, async (g) =>
    (await g.users.labels.create({
      userId: 'me',
      requestBody: { name, labelListVisibility: 'labelShow', messageListVisibility: 'show' },
    })).data
  );
}

// The last line of defense for "never delete": nothing may add TRASH or SPAM.
export function assertSafeLabels(add = []) {
  for (const id of add) {
    if (FORBIDDEN_LABELS.has(String(id).toUpperCase())) throw new Error('Moving mail to Trash or Spam is not allowed.');
  }
}

// Adds or removes labels on a list of IDs, or on everything a search matches.
// Archive = remove INBOX. Mark as read = remove UNREAD. Returns how many messages
// the change was applied to.
export function relabel(email, { ids = [], query, max = 500, add = [], remove = [] }) {
  if (!add.length && !remove.length) throw new Error('Nothing to change: pass labels to add or remove.');
  assertSafeLabels(add);
  return run(email, async (g) => {
    const limit = Math.min(Math.max(Number(max) || 500, 1), 5000);
    const all = [...ids].slice(0, limit);
    if (query) {
      let pageToken;
      while (all.length < limit) {
        const { data } = await g.users.messages.list({
          userId: 'me', q: query, maxResults: Math.min(500, limit - all.length), pageToken,
        });
        all.push(...(data.messages ?? []).map((m) => m.id));
        pageToken = data.nextPageToken;
        if (!pageToken) break;
      }
    }
    for (let i = 0; i < all.length; i += 1000) {
      await g.users.messages.batchModify({
        userId: 'me',
        requestBody: { ids: all.slice(i, i + 1000), addLabelIds: add, removeLabelIds: remove },
      });
    }
    return all.length;
  });
}

export function listFilters(email) {
  return run(email, async (g) => (await g.users.settings.filters.list({ userId: 'me' })).data.filter ?? []);
}

// The action is rebuilt here from two label lists, so a filter can never forward
// mail or send it to Trash or Spam, whatever the caller passes in.
export function filterAction({ add = [], remove = [] }) {
  if (!add.length && !remove.length) throw new Error('A filter needs at least one label to add or remove.');
  assertSafeLabels(add);
  return { addLabelIds: [...add], removeLabelIds: [...remove] };
}

export function createFilter(email, criteria, labelChanges) {
  const action = filterAction(labelChanges);
  return run(email, async (g) =>
    (await g.users.settings.filters.create({ userId: 'me', requestBody: { criteria, action } })).data
  );
}

export function deleteFilter(email, id) {
  return run(email, async (g) => g.users.settings.filters.delete({ userId: 'me', id }));
}

// --- Drafts -----------------------------------------------------------------

function noNewlines(value, field) {
  if (/[\r\n]/.test(value)) throw new Error(`${field} can't contain line breaks.`);
  return value;
}

// RFC 2047 encoded-words, split so each stays under the 75 character limit.
function encodeWords(text) {
  if (!/[^\x20-\x7e]/.test(text)) return text;
  const words = [];
  let chunk = '';
  for (const ch of text) {
    if (Buffer.byteLength(chunk + ch) > 45) {
      words.push(chunk);
      chunk = '';
    }
    chunk += ch;
  }
  words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w).toString('base64')}?=`).join('\r\n ');
}

// "José Pérez <jose@x.com>, ana@y.com" -> display names encoded, addresses untouched.
export function encodeAddresses(list) {
  return list
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => {
      const m = a.match(/^(.*?)\s*<([^<>]+)>$/);
      if (!m || !m[1]) return a;
      const name = m[1].replace(/^"|"$/g, '');
      return /[^\x20-\x7e]/.test(name) ? `${encodeWords(name)} <${m[2]}>` : `"${name.replace(/"/g, '')}" <${m[2]}>`;
    })
    .join(', ');
}

export function buildDraft({ from, to, cc, subject, body, inReplyTo, references }) {
  if (!to) throw new Error('A draft needs a recipient (to), or reply_to_id to answer an email.');
  const lines = [
    `From: ${noNewlines(from, 'from')}`,
    `To: ${encodeAddresses(noNewlines(to, 'to'))}`,
    cc ? `Cc: ${encodeAddresses(noNewlines(cc, 'cc'))}` : null,
    subject ? `Subject: ${encodeWords(noNewlines(subject, 'subject'))}` : null,
    inReplyTo ? `In-Reply-To: ${noNewlines(inReplyTo, 'In-Reply-To')}` : null,
    references ? `References: ${noNewlines(references, 'References')}` : null,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
  ].filter(Boolean);
  return `${lines.join('\r\n')}\r\n\r\n${String(body ?? '').replace(/\r?\n/g, '\r\n')}`;
}

// Only creates the draft. Sending it is up to you, from Gmail.
export function createDraft(email, { to, cc, subject, body, replyTo }) {
  return run(email, async (g) => {
    let threadId;
    let inReplyTo;
    let references;
    if (replyTo) {
      const { data: m } = await g.users.messages.get({
        userId: 'me',
        id: replyTo,
        format: 'metadata',
        metadataHeaders: ['Message-ID', 'References', 'Subject', 'From', 'Reply-To'],
      });
      const h = m.payload?.headers;
      threadId = m.threadId;
      to ||= header(h, 'Reply-To') || header(h, 'From');
      const original = header(h, 'Subject');
      subject ||= /^re:/i.test(original) ? original : `Re: ${original}`;
      inReplyTo = header(h, 'Message-ID') || undefined;
      references = [header(h, 'References'), inReplyTo].filter(Boolean).join(' ') || undefined;
    }
    const raw = buildDraft({ from: email, to, cc, subject, body, inReplyTo, references });
    const { data } = await g.users.drafts.create({
      userId: 'me',
      requestBody: { message: { raw: Buffer.from(raw).toString('base64url'), threadId } },
    });
    return data.id;
  });
}
