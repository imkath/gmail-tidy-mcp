// Defenses for what third parties put in mail: hidden text aimed at the model,
// dangerous attachments and phishing signs. Everything here only flags or strips;
// the real guarantee is still that no tool can send or delete mail.
import { extname } from 'node:path';
import { unzip } from './files.js';

// Unicode tag characters can spell out ASCII that is invisible on screen but read by
// a model ("ASCII smuggling"); they have no legitimate use in mail, so they are what
// gets reported. Zero-width characters, bidi controls and soft hyphens are removed
// quietly: newsletters use them as preview padding.
const INVISIBLE = /[\u{E0000}-\u{E007F}\u{200B}-\u{200F}\u{2060}-\u{2064}\u{FEFF}\u{202A}-\u{202E}\u{2066}-\u{2069}\u{AD}]/gu;
const TAG = /[\u{E0000}-\u{E007F}]/u;

export function stripInvisible(text) {
  let removed = 0;
  let tags = 0;
  const clean = String(text).replace(INVISIBLE, (c) => {
    removed++;
    if (TAG.test(c)) tags++;
    return '';
  });
  return { text: clean, removed, tags };
}

// Phrases that only make sense as instructions to an AI. A match is a warning, not
// proof: a security newsletter can quote them. Missing a match proves nothing either.
const INJECTION = [
  [/ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|messages|rules)/i, 'asks to ignore previous instructions'],
  [/disregard (all |any |the )?(previous|prior|above|system)/i, 'asks to disregard instructions'],
  [/(you are|act as|you're) now (a|an|the) /i, 'tries to change the assistant role'],
  [/\b(system|developer) (prompt|message|instructions)\b/i, 'mentions the system prompt'],
  [/<\|?(im_start|im_end|system|assistant)\|?>|\[\/?INST\]|<\/?(system|tool_call)>/i, 'contains chat-format control tokens'],
  [/\b(as an? (ai|assistant|language model)|dear (ai|assistant|claude|chatgpt|gpt))\b/i, 'addresses an AI assistant'],
  [/\b(organize_emails|create_filter|delete_filter|create_draft|connect_account|get_attachment|update_label|set_signature)\b/, 'names the tools of this server'],
  [/\b(forward|send|email|reply)\b.{0,40}\b(this|these|all|every)\b.{0,40}\b(to|at)\b\s*\S+@\S+/i, 'asks to send mail to an address'],
  [/(do not|don't) (tell|inform|mention|show) (the )?(user|human|owner)/i, 'asks to hide something from the user'],
];

export function injectionSignals(text) {
  return INJECTION.filter(([re]) => re.test(text)).map(([, why]) => why);
}

const EXECUTABLE = new Set([
  '.exe', '.scr', '.com', '.pif', '.cpl', '.msi', '.msp', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.wsh', '.hta', '.jar', '.lnk', '.reg', '.dll', '.sys', '.app', '.dmg', '.pkg', '.command', '.sh', '.iso', '.img',
  '.vhd', '.appx', '.msix', '.apk', '.scpt', '.workflow', '.chm', '.url', '.library-ms', '.inf',
]);
const MACRO_OFFICE = new Set(['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.xlam', '.ppam', '.ppsm']);
const DOC_EXT = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.xml', '.html']);

// What the bytes actually are, from their first bytes.
export function sniff(bytes) {
  const b = bytes.subarray(0, 8);
  if (b[0] === 0x4d && b[1] === 0x5a) return 'windows-executable';
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'linux-executable';
  const m = b.readUInt32BE?.(0);
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(m)) return 'mac-executable';
  if (b[0] === 0x23 && b[1] === 0x21) return 'script';
  if (b.toString('latin1', 0, 5) === '%PDF-') return 'pdf';
  if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return 'zip';
  if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return 'ole'; // old Office
  return 'other';
}

function zipEncrypted(bytes) {
  // General purpose flag bit 0 of the first local header means "encrypted".
  return bytes.length > 8 && bytes.readUInt32LE(0) === 0x04034b50 && (bytes.readUInt16LE(6) & 1) === 1;
}

// Returns { block, warnings }. block = it should not be written to disk unless the
// user explicitly asked for that specific file.
export function attachmentRisks(filename, bytes) {
  const warnings = [];
  let block = false;
  const name = String(filename);
  const ext = extname(name).toLowerCase();
  const kind = sniff(bytes);

  if (/[\u{202A}-\u{202E}\u{2066}-\u{2069}]/u.test(name)) {
    warnings.push('the file name contains characters that reverse text direction, a trick to disguise the real extension');
    block = true;
  }
  if (EXECUTABLE.has(ext)) {
    warnings.push(`${ext} files can run code`);
    block = true;
  }
  const inner = extname(name.slice(0, -ext.length)).toLowerCase();
  if (ext && DOC_EXT.has(inner) && EXECUTABLE.has(ext)) warnings.push(`double extension (${inner}${ext}) disguises an executable as a document`);
  if (kind.endsWith('executable') || (kind === 'script' && !['.sh', '.py', '.rb', '.pl'].includes(ext))) {
    warnings.push(`the content is a ${kind.replace('-', ' ')} even though the name ends in ${ext || 'nothing'}`);
    block = true;
  }
  if (kind === 'pdf') {
    const text = bytes.toString('latin1');
    const active = ['/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA', '/EmbeddedFile', '/SubmitForm']
      .filter((k) => new RegExp(`${k.replace('/', '\\/')}[\\s/<\\[(]`).test(text));
    if (active.length) warnings.push(`the PDF has active content (${active.join(', ')}); open it only if you trust the sender`);
  }
  if (kind === 'zip') {
    if (zipEncrypted(bytes)) warnings.push('the archive is password-protected, a common way to slip malware past scanners');
    try {
      const entries = unzip(bytes);
      if (MACRO_OFFICE.has(ext) || entries.some((e) => /vbaProject\.bin$/i.test(e.name))) warnings.push('the document contains macros');
      const bad = entries.map((e) => e.name).filter((n) => EXECUTABLE.has(extname(n).toLowerCase()) || /[\u{202A}-\u{202E}]/u.test(n));
      if (bad.length) {
        warnings.push(`the archive contains files that can run code: ${bad.slice(0, 5).join(', ')}`);
        block = true;
      }
    } catch {
      // Encrypted or damaged: already flagged above, or not worth guessing.
    }
  } else if (MACRO_OFFICE.has(ext) || kind === 'ole') {
    if (MACRO_OFFICE.has(ext)) warnings.push('macro-enabled Office file');
    else warnings.push('old-format Office file, which can carry macros');
  }
  return { block, warnings };
}

function domainOf(address) {
  return String(address).toLowerCase().match(/@([a-z0-9.-]+)/)?.[1] ?? '';
}

// Registrable-ish domain: last two labels, or three for things like .co.uk / .com.ar.
export function baseDomain(host) {
  const parts = String(host).toLowerCase().replace(/^www\./, '').split('.').filter(Boolean);
  const n = parts.length >= 3 && /^(co|com|org|net|gob|gov|edu|ac)$/.test(parts[parts.length - 2]) ? 3 : 2;
  return parts.slice(-n).join('.');
}

const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com',
  'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'yandex.com', 'zoho.com']);

// Gmail and Outlook wrap links in their own redirect when mail is forwarded or
// scanned; the destination that matters is the one inside.
export function unwrapLink(href) {
  try {
    const url = new URL(href);
    const host = url.hostname.toLowerCase();
    const inner =
      (/(^|\.)google\.[a-z.]+$/.test(host) && url.pathname === '/url' && (url.searchParams.get('q') || url.searchParams.get('url'))) ||
      (/safelinks\.protection\.outlook\.com$/.test(host) && url.searchParams.get('url'));
    return inner && /^https?:\/\//i.test(inner) ? inner : href;
  } catch {
    return href;
  }
}

// A link host that is a bare IP or a punycode lookalike (xn--) is suspicious anywhere.
function oddHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /(^|\.)xn--/i.test(host);
}

// Phishing signs from headers and from the HTML links. Tuned to stay quiet on normal
// newsletters (tracking links, sending platforms) so a warning still means something.
export function mailRisks({ from = '', replyTo = '', authResults = '', html = '', bulk = false }) {
  const warnings = [];
  const fromDomain = domainOf(from.match(/<([^>]+)>/)?.[1] ?? from);

  let authFailed = false;
  for (const check of ['spf', 'dkim', 'dmarc']) {
    const m = authResults.match(new RegExp(`\\b${check}=(fail|softfail|permerror|none)\\b`, 'i'));
    if (m && !(check === 'spf' && m[1] === 'none')) {
      authFailed = true;
      warnings.push(`${check.toUpperCase()} ${m[1].toLowerCase()}: the sender may be forged`);
    }
  }
  if (replyTo) {
    const replyDomain = domainOf(replyTo);
    const differs = replyDomain && fromDomain && baseDomain(replyDomain) !== baseDomain(fromDomain);
    if (differs && (authFailed || (FREE_MAIL.has(replyDomain) && !FREE_MAIL.has(fromDomain)))) {
      warnings.push(`replies would go to ${replyDomain}, not to the sender's domain ${fromDomain}`);
    }
  }
  const displayName = from.replace(/<[^>]*>/, '');
  const shown = displayName.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i)?.[1];
  if (shown && fromDomain && baseDomain(shown) !== baseDomain(fromDomain)) {
    warnings.push(`the display name shows an address at ${shown} but the mail comes from ${fromDomain}`);
  }
  const mismatched = new Set();
  const odd = new Set();
  for (const [, href, label] of html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const realHost = unwrapLink(href.replace(/&amp;/g, '&')).match(/^https?:\/\/([^/:?#]+)/i)?.[1];
    if (!realHost) continue;
    if (oddHost(realHost)) odd.add(realHost);
    // Mailing lists route every link through a click tracker; only one-to-one mail is judged.
    if (bulk) continue;
    const shownHost = label.replace(/<[^>]+>/g, '').trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)/i)?.[1];
    if (shownHost && baseDomain(shownHost) !== baseDomain(realHost)) mismatched.add(`${shownHost} -> ${realHost}`);
  }
  if (odd.size) warnings.push(`links go to an IP address or a lookalike (punycode) domain: ${[...odd].slice(0, 3).join(', ')}`);
  if (mismatched.size) warnings.push(`links show one site but go to another: ${[...mismatched].slice(0, 3).join(', ')}`);
  return warnings;
}
