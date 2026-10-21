// Read and organize: search, read, label, archive, filters and drafts.
// Never send and never delete. test/safety.test.js scans the code and fails if a
// send, trash or delete call shows up, and the label checks below keep mail out of
// Trash and Spam even if a caller asks for it.
import { google } from 'googleapis';
import { authedClient, isTokenError } from './auth.js';
import { injectionSignals, mailRisks, stripInvisible } from './security.js';
import { listAccounts } from './store.js';

const MAX_BODY = 40_000;
const FORBIDDEN_LABELS = new Set(['TRASH', 'SPAM']);

function api(email) {
  return google.gmail({ version: 'v1', auth: authedClient(email) });
}

function isQuotaError(err) {
  const code = err?.code ?? err?.response?.status;
  const reason = JSON.stringify(err?.errors ?? err?.response?.data ?? '');
  return code === 429 || (code === 403 && /rateLimit|quota/i.test(reason));
}

async function run(email, fn) {
  try {
    return await fn(api(email));
  } catch (err) {
    if (isTokenError(err)) throw new Error(`Access to ${email} expired or was revoked. Reconnect it with connect_account.`);
    if (isQuotaError(err)) throw new Error(`Gmail is rate-limiting ${email} for about a minute. Wait a bit, or scan fewer emails (max).`);
    throw err;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Fetches many messages a few at a time. When Gmail answers with a quota error the
// batch waits and retries (up to about a minute and a half in total, which covers
// Gmail's per-minute window), so a big scan slows down instead of dying halfway.
const BACKOFF_MS = [2000, 4000, 8000, 16000, 25000, 35000];

async function fetchEach(ids, fn, size = 10) {
  const out = [];
  for (let i = 0; i < ids.length; i += size) {
    const slice = ids.slice(i, i + size);
    for (let attempt = 0; ; attempt++) {
      try {
        out.push(...(await Promise.all(slice.map(fn))));
        break;
      } catch (err) {
        if (!isQuotaError(err) || attempt >= BACKOFF_MS.length) throw err;
        await sleep(BACKOFF_MS[attempt]);
      }
    }
  }
  return out;
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
    return fetchEach(
      (data.messages ?? []).map((m) => m.id),
      async (id) => {
        const { data: m } = await g.users.messages.get({
          userId: 'me',
          id,
          format: 'metadata',
          metadataHeaders: ['From', 'To', 'Subject', 'Date'],
        });
        const h = m.payload?.headers;
        return {
          id: m.id,
          threadId: m.threadId,
          from: header(h, 'From'),
          subject: header(h, 'Subject'),
          date: header(h, 'Date'),
          snippet: stripInvisible(m.snippet ?? '').text.replace(/[\u0000-\u001f\u007f]+/g, ' '),
          labels: m.labelIds ?? [],
        };
      }
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
      own: listAccounts().map((a) => a.email),
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
    const froms = await fetchEach(ids, (id) =>
      g.users.messages.get({ userId: 'me', id, format: 'metadata', metadataHeaders: ['From'] }).then(({ data }) => header(data.payload?.headers, 'From')));
    for (const from of froms) {
      const address = senderAddress(from);
      if (!address) continue;
      const s = senders.get(address) ?? { address, name: from.replace(/<[^>]*>/, '').replace(/"/g, '').trim(), count: 0 };
      s.count++;
      senders.set(address, s);
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

// Content-Disposition for a file name. Gmail shows the plain filename parameter and
// ignores the RFC 2231 form, so a name with accents (Cotización.pdf) goes as an
// encoded-word there, the way Gmail itself writes it, plus filename* for strict clients.
export function dispositionFor(filename) {
  const name = noNewlines(String(filename), 'attachment name');
  if (!/[^\x20-\x7e]/.test(name)) return `attachment; filename="${name.replace(/["\\]/g, '_')}"`;
  const word = `=?UTF-8?B?${Buffer.from(name).toString('base64')}?=`;
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${word}"; filename*=UTF-8''${encoded}`;
}

export function buildDraft({ from, to, cc, subject, body, inReplyTo, references, attachments = [], boundary }) {
  if (!to) throw new Error('A draft needs a recipient (to), or reply_to_id to answer an email.');
  const lines = [
    `From: ${noNewlines(from, 'from')}`,
    `To: ${encodeAddresses(noNewlines(to, 'to'))}`,
    cc ? `Cc: ${encodeAddresses(noNewlines(cc, 'cc'))}` : null,
    subject ? `Subject: ${encodeWords(noNewlines(subject, 'subject'))}` : null,
    inReplyTo ? `In-Reply-To: ${noNewlines(inReplyTo, 'In-Reply-To')}` : null,
    references ? `References: ${noNewlines(references, 'References')}` : null,
    'MIME-Version: 1.0',
  ].filter(Boolean);
  const text = String(body ?? '').replace(/\r?\n/g, '\r\n');
  if (!attachments.length) {
    return `${[...lines, 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: 8bit'].join('\r\n')}\r\n\r\n${text}`;
  }
  const b = boundary ?? `gmail-tidy-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  const parts = [
    `--${b}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${text}`,
    ...attachments.map((a) => {
      const type = noNewlines(String(a.mimeType || 'application/octet-stream'), 'attachment type');
      const data = Buffer.from(a.bytes).toString('base64').replace(/.{76}/g, '$&\r\n');
      return `--${b}\r\nContent-Type: ${type}\r\nContent-Disposition: ${dispositionFor(a.filename)}\r\nContent-Transfer-Encoding: base64\r\n\r\n${data}`;
    }),
  ];
  return `${[...lines, `Content-Type: multipart/mixed; boundary="${b}"`].join('\r\n')}\r\n\r\n${parts.join('\r\n')}\r\n--${b}--\r\n`;
}

// Only creates the draft. Sending it is up to you, from Gmail.
export function createDraft(email, { to, cc, subject, body, replyTo, attachments = [] }) {
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
    const raw = buildDraft({ from: email, to, cc, subject, body, inReplyTo, references, attachments });
    const { data } = await g.users.drafts.create({
      userId: 'me',
      requestBody: { message: { raw: Buffer.from(raw).toString('base64url'), threadId } },
    });
    return data.id;
  });
}


// --- Threads ------------------------------------------------------------------

// Drops the quoted history that each reply repeats ("El lun, ... escribió:" and the
// "> " lines after it), so a long thread fits and each message shows what it added.
export function trimQuoted(text) {
  const lines = String(text).split('\n');
  const cut = lines.findIndex((l, i) =>
    /^\s*(On .{4,200} wrote:|El .{4,200} escribi[oó]:|-{2,}\s*(Original Message|Mensaje original)\s*-{2,}|From: .+ <.+@.+>)\s*$/i.test(l) &&
    lines.slice(i + 1, i + 4).some((n) => /^\s*>|^\s*$/.test(n)));
  const kept = (cut >= 0 ? lines.slice(0, cut) : lines).filter((l) => !/^\s*>/.test(l));
  return kept.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}

const MAX_THREAD = 60_000;

// A whole conversation, oldest first. Accepts a thread ID or the ID of any message in it.
export function getThread(email, id, own = []) {
  return run(email, async (g) => {
    let threadId = id;
    let data;
    try {
      data = (await g.users.threads.get({ userId: 'me', id: threadId, format: 'full' })).data;
    } catch {
      threadId = (await g.users.messages.get({ userId: 'me', id, format: 'minimal' })).data.threadId;
      data = (await g.users.threads.get({ userId: 'me', id: threadId, format: 'full' })).data;
    }
    const messages = (data.messages ?? []).map((m, i, all) => {
      const h = m.payload?.headers;
      const cleaned = stripInvisible(extractBody(m.payload));
      const body = i === 0 ? cleaned.text.trim() : trimQuoted(cleaned.text);
      const security = mailRisks({
        from: header(h, 'From'),
        replyTo: header(h, 'Reply-To'),
        authResults: header(h, 'Authentication-Results'),
        html: firstHtml(m.payload),
        bulk: Boolean(header(h, 'List-Unsubscribe') || header(h, 'List-Id')),
        own,
      });
      if (cleaned.tags) security.push(`${cleaned.tags} invisible "tag" characters were removed: they are used to hide instructions for AI`);
      for (const why of injectionSignals(body)) security.push(`possible prompt injection: ${why}`);
      return {
        id: m.id,
        from: header(h, 'From'),
        to: header(h, 'To'),
        date: header(h, 'Date'),
        subject: header(h, 'Subject'),
        attachments: listAttachments(m.payload).map(({ part, filename, size }) => ({ part, filename, size })),
        body,
        security,
        last: i === all.length - 1,
      };
    });
    // Over budget, older messages shrink first: the latest ones matter most for a reply.
    let total = messages.reduce((n, m) => n + m.body.length, 0);
    for (const m of messages) {
      if (total <= MAX_THREAD || m.last) break;
      const keep = Math.max(400, m.body.length - (total - MAX_THREAD));
      if (keep < m.body.length) {
        total -= m.body.length - keep;
        m.body = m.body.slice(0, keep) + '\n[... shortened to fit the thread ...]';
      }
    }
    return { threadId, messages };
  });
}

// --- Newsletters --------------------------------------------------------------

// Parses List-Unsubscribe ("<https://...>, <mailto:...>") into its links.
export function unsubscribeLinks(value = '') {
  const links = [...String(value).matchAll(/<([^>]+)>/g)].map((m) => m[1].trim());
  return {
    web: links.find((l) => /^https:\/\//i.test(l)) ?? links.find((l) => /^http:\/\//i.test(l)) ?? null,
    mail: links.find((l) => /^mailto:/i.test(l)) ?? null,
  };
}

// Mailing lists that wrote in a period, by volume, with how to leave each one.
// It only reports: unsubscribing means visiting a site or sending mail, which is the
// user's call, not something this server does on its own.
export function newsletters(email, query, max = 500) {
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
    const lists = new Map();
    const metas = await fetchEach(ids, (id) =>
      g.users.messages.get({ userId: 'me', id, format: 'metadata', metadataHeaders: ['From', 'List-Unsubscribe', 'List-Unsubscribe-Post', 'Date'] })
        .then(({ data }) => data));
    {
      for (const m of metas) {
        const h = m.payload?.headers;
        const unsub = header(h, 'List-Unsubscribe');
        if (!unsub) continue;
        const address = senderAddress(header(h, 'From'));
        if (!address) continue;
        const entry = lists.get(address) ?? {
          address,
          name: header(h, 'From').replace(/<[^>]*>/, '').replace(/"/g, '').trim(),
          count: 0,
          unread: 0,
          oneClick: false,
          ...unsubscribeLinks(unsub),
          last: header(h, 'Date'),
        };
        entry.count++;
        if ((m.labelIds ?? []).includes('UNREAD')) entry.unread++;
        if (/One-Click/i.test(header(h, 'List-Unsubscribe-Post'))) entry.oneClick = true;
        lists.set(address, entry);
      }
    }
    return { scanned: ids.length, lists: [...lists.values()].sort((a, b) => b.count - a.count) };
  });
}

// --- Editing drafts -----------------------------------------------------------

export function listDrafts(email, max = 20) {
  const n = Math.min(Math.max(Number(max) || 20, 1), 100);
  return run(email, async (g) => {
    const { data } = await g.users.drafts.list({ userId: 'me', maxResults: n });
    return fetchEach((data.drafts ?? []).map((d) => d.id), async (id) => {
      const { data: d } = await g.users.drafts.get({ userId: 'me', id, format: 'full' });
      const h = d.message?.payload?.headers;
      return {
        id,
        to: header(h, 'To'),
        subject: header(h, 'Subject'),
        date: header(h, 'Date'),
        attachments: listAttachments(d.message?.payload).map((a) => a.filename),
        snippet: stripInvisible(d.message?.snippet ?? '').text,
        threadId: d.message?.threadId,
      };
    });
  });
}

// Rewrites a draft keeping whatever isn't given: recipients, subject, text, the
// thread it answers and its current attachments. Gmail only replaces drafts whole,
// so the old attachments are read back and sent again unless asked to drop them.
export function updateDraft(email, id, { to, cc, subject, body, attachments = [], keepAttachments = true }) {
  return run(email, async (g) => {
    const { data: d } = await g.users.drafts.get({ userId: 'me', id, format: 'full' });
    const m = d.message;
    const h = m?.payload?.headers;
    const kept = [];
    if (keepAttachments) {
      for (const a of listAttachments(m?.payload)) {
        const data = a.data ?? (await g.users.messages.attachments.get({ userId: 'me', messageId: m.id, id: a.attachmentId })).data.data;
        kept.push({ filename: a.filename, mimeType: a.mimeType, bytes: Buffer.from(data, 'base64url') });
      }
    }
    const raw = buildDraft({
      from: email,
      to: to ?? header(h, 'To'),
      cc: cc ?? (header(h, 'Cc') || undefined),
      subject: subject ?? (header(h, 'Subject') || undefined),
      body: body ?? extractBody(m?.payload),
      inReplyTo: header(h, 'In-Reply-To') || undefined,
      references: header(h, 'References') || undefined,
      attachments: [...kept, ...attachments],
    });
    const { data } = await g.users.drafts.update({
      userId: 'me',
      id,
      requestBody: { id, message: { raw: Buffer.from(raw).toString('base64url'), threadId: m?.threadId } },
    });
    return { id: data.id, attachments: [...kept, ...attachments].map((a) => a.filename) };
  });
}
