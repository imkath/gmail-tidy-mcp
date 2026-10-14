// Read and organize: search, read, label, archive, filters and drafts.
// Never send and never delete. test/safety.test.js scans the code and fails if a
// send, trash or delete call shows up, and the label checks below keep mail out of
// Trash and Spam even if a caller asks for it.
import { google } from 'googleapis';
import { authedClient, isTokenError } from './auth.js';
import { injectionSignals, mailRisks, stripInvisible } from './security.js';

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
  return stripInvisible(value).text.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
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
    .replace(/<(\w+)[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d])|max-height\s*:\s*0(?![.\d]))[^>]*>[\s\S]*?<\/\1>/gi, ' ')
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

function firstHtml(payload) {
  if (!payload) return '';
  if (payload.mimeType === 'text/html' && payload.body?.data) return decode(payload);
  for (const part of payload.parts ?? []) {
    const html = firstHtml(part);
    if (html) return html;
  }
  return '';
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
          snippet: stripInvisible(m.snippet ?? '').text.replace(/[\u0000-\u001f\u007f]+/g, ' '),
          labels: m.labelIds ?? [],
        };
      })
    );
  });
}

// Every part with a file name, in document order. partId is stable for a message,
// unlike attachmentId, so it's what tools hand back to the caller. When the whole
// message is the file (DMARC reports often are), Gmail leaves partId empty: that
// one is called "0", which can't clash because such a message has no other parts.
export function listAttachments(payload) {
  const out = [];
  const walk = (part) => {
    if (part?.filename && part.body) {
      out.push({ part: part.partId || '0', filename: part.filename, mimeType: part.mimeType, size: part.body.size ?? 0, attachmentId: part.body.attachmentId, data: part.body.data });
    }
    for (const p of part?.parts ?? []) walk(p);
  };
  walk(payload);
  return out;
}

export function getMessage(email, id) {
  return run(email, async (g) => {
    const { data: m } = await g.users.messages.get({ userId: 'me', id, format: 'full' });
    const h = m.payload?.headers;
    const cleaned = stripInvisible(extractBody(m.payload));
    let body = cleaned.text;
    if (body.length > MAX_BODY) body = body.slice(0, MAX_BODY) + '\n[... body truncated ...]';
    const security = mailRisks({
      from: header(h, 'From'),
      replyTo: header(h, 'Reply-To'),
      authResults: header(h, 'Authentication-Results'),
      html: firstHtml(m.payload),
      bulk: Boolean(header(h, 'List-Unsubscribe') || header(h, 'List-Id')),
    });
    if (cleaned.tags) security.push(`${cleaned.tags} invisible "tag" characters were removed from the text: they are used to hide instructions for AI`);
    for (const why of injectionSignals(body)) security.push(`possible prompt injection: ${why}`);
    return {
      security,
      from: header(h, 'From'),
      to: header(h, 'To'),
      cc: header(h, 'Cc'),
      subject: header(h, 'Subject'),
      date: header(h, 'Date'),
      labels: m.labelIds ?? [],
      attachments: listAttachments(m.payload).map(({ part, filename, mimeType, size }) => ({ part, filename, mimeType, size })),
      body,
    };
  });
}

// Finds an attachment by part ID or file name and returns its bytes.
export function getAttachment(email, messageId, which) {
  return run(email, async (g) => {
    const { data: m } = await g.users.messages.get({ userId: 'me', id: messageId, format: 'full' });
    const all = listAttachments(m.payload);
    const hit = all.find((a) => a.part === which) ?? all.find((a) => a.filename.toLowerCase() === String(which).toLowerCase());
    if (!hit) {
      const names = all.map((a) => `${a.part} ${a.filename}`).join(', ') || 'none';
      throw new Error(`No attachment "${which}" in that email. Attachments: ${names}.`);
    }
    let data = hit.data;
    if (!data) {
      data = (await g.users.messages.attachments.get({ userId: 'me', messageId, id: hit.attachmentId })).data.data;
    }
    return { filename: hit.filename, mimeType: hit.mimeType, bytes: Buffer.from(data, 'base64url') };
  });
}

// "Name <a@b.com>" or "a@b.com" -> lowercase address. Empty when there is none.
export function senderAddress(from) {
  const m = String(from).match(/<([^<>\s]+@[^<>\s]+)>/) ?? String(from).match(/([^\s<>"]+@[^\s<>"]+)/);
  return m ? m[1].toLowerCase() : '';
}

// Counts senders over a search. Only the From header is fetched, a few at a time.
export function senderStats(email, query, max = 500) {
  const limit = Math.min(Math.max(Number(max) || 500, 1), 2000);
  return run(email, async (g) => {
    const ids = [];
    let pageToken;
    while (ids.length < limit) {
      const { data } = await g.users.messages.list({ userId: 'me', q: query, maxResults: Math.min(500, limit - ids.length), pageToken });
      ids.push(...(data.messages ?? []).map((m) => m.id));
      pageToken = data.nextPageToken;
      if (!pageToken) break;
    }
    const senders = new Map();
    for (let i = 0; i < ids.length; i += 20) {
      const batch = await Promise.all(
        ids.slice(i, i + 20).map((id) =>
          g.users.messages.get({ userId: 'me', id, format: 'metadata', metadataHeaders: ['From'] }).then(({ data }) => header(data.payload?.headers, 'From'))
        )
      );
      for (const from of batch) {
        const address = senderAddress(from);
        if (!address) continue;
        const s = senders.get(address) ?? { address, name: from.replace(/<[^>]*>/, '').replace(/"/g, '').trim(), count: 0 };
        s.count++;
        senders.set(address, s);
      }
    }
    return { scanned: ids.length, senders: [...senders.values()].sort((a, b) => b.count - a.count) };
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

// Gmail only accepts colors from its own palette; the API names the bad value if one
// isn't in it. This only checks the shape so a typo fails before the request.
export function labelColor(background, text = '#ffffff') {
  for (const c of [background, text]) {
    if (!/^#[0-9a-f]{6}$/i.test(String(c))) throw new Error(`"${c}" is not a hex color like #fb4c2f.`);
  }
  return { backgroundColor: background.toLowerCase(), textColor: text.toLowerCase() };
}

const SIDEBAR = { show: 'labelShow', hide: 'labelHide', unread: 'labelShowIfUnread' };

// Builds the patch for update_label from only the fields the caller gave, so
// nothing else about the label changes.
export function labelPatch({ name, background, text, sidebar, inMessageList }) {
  const patch = {};
  if (name !== undefined) {
    if (!String(name).trim()) throw new Error('The new name cannot be empty.');
    patch.name = String(name).trim();
  }
  if (background !== undefined) patch.color = labelColor(background, text);
  else if (text !== undefined) throw new Error('Pass background together with text.');
  if (sidebar !== undefined) {
    if (!SIDEBAR[sidebar]) throw new Error('sidebar must be show, hide or unread.');
    patch.labelListVisibility = SIDEBAR[sidebar];
  }
  if (inMessageList !== undefined) patch.messageListVisibility = inMessageList ? 'show' : 'hide';
  if (!Object.keys(patch).length) throw new Error('Nothing to change: pass a new name, a color or a visibility.');
  return patch;
}

export function updateLabel(email, id, changes) {
  const requestBody = labelPatch(changes);
  return run(email, async (g) => (await g.users.labels.patch({ userId: 'me', id, requestBody })).data);
}

// Only the signature field is sent, so this can't change the reply-to address,
// the display name or anything else about how mail goes out.
export function setSignature(email, sendAsEmail, signature) {
  return run(email, async (g) =>
    (await g.users.settings.sendAs.patch({ userId: 'me', sendAsEmail: sendAsEmail ?? email, requestBody: { signature } })).data
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
