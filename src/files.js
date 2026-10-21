// Attachments: unpack .gz and .zip (DMARC reports arrive like that), decide what can
// be shown as text, and save the rest under one folder. A file name comes from the
// sender, so it's reduced to a bare name before it touches the disk.
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import { basename, extname, join, relative, sep } from 'node:path';

export const MAX_INLINE = 40_000;
const MAX_UNPACKED = 20 * 1024 * 1024; // zip bomb guard

export const DOWNLOADS = process.env.GMAIL_TIDY_DOWNLOADS ?? join(homedir(), 'Downloads', 'gmail-tidy-mcp');

const TEXT_TYPES = /^(text\/|application\/(json|xml|csv|x-yaml|yaml)|.*\+xml$|.*\+json$)/i;
const TEXT_EXT = new Set(['.txt', '.csv', '.tsv', '.json', '.xml', '.md', '.log', '.html', '.htm', '.ics', '.eml', '.yaml', '.yml']);

export function isText(filename, mimeType = '') {
  return TEXT_TYPES.test(mimeType) || TEXT_EXT.has(extname(filename).toLowerCase());
}

// Reads the central directory, which has the real sizes even when the local
// headers defer them to a data descriptor. Supports stored and deflated entries.
export function unzip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a zip file.');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries = [];
  let total = 0;
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Damaged zip file.');
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    total += size;
    if (total > MAX_UNPACKED) throw new Error('The zip unpacks to more than 20 MB; save it instead.');
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + compressed);
    if (method === 0) entries.push({ name, data: raw });
    else if (method === 8) entries.push({ name, data: inflateRawSync(raw, { maxOutputLength: MAX_UNPACKED }) });
    else throw new Error(`Zip entry ${name} uses an unsupported compression method (${method}).`);
  }
  return entries;
}

// Returns the readable text inside an attachment, or null when it isn't text.
export function readableText(filename, mimeType, bytes) {
  const ext = extname(filename).toLowerCase();
  if (ext === '.gz' || /gzip/i.test(mimeType)) {
    const inner = filename.replace(/\.gz$/i, '');
    return readableText(inner, '', gunzipSync(bytes, { maxOutputLength: MAX_UNPACKED }));
  }
  if (ext === '.zip' || /zip/i.test(mimeType)) {
    const texts = unzip(bytes)
      .filter((e) => isText(e.name))
      .map((e) => `=== ${basename(e.name)} ===\n${e.data.toString('utf8')}`);
    return texts.length ? texts.join('\n\n') : null;
  }
  return isText(filename, mimeType) ? bytes.toString('utf8') : null;
}

// Keeps only the last path segment and drops characters that are unsafe in file
// names, so "../../.ssh/authorized_keys" becomes "authorized_keys".
export function safeName(filename) {
  const name = basename(String(filename).replace(/\\/g, '/'))
    .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_')
    .replace(/^\.+/, '')
    .trim();
  return name || 'attachment';
}

// Never overwrites: a second "factura.pdf" becomes "factura (2).pdf".
export function saveFile(dir, filename, bytes) {
  mkdirSync(dir, { recursive: true });
  const name = safeName(filename);
  const ext = extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let path = join(dir, name);
  for (let i = 2; existsSync(path); i++) path = join(dir, `${stem} (${i})${ext}`);
  writeFileSync(path, bytes, { flag: 'wx' });
  quarantine(path);
  return path;
}

// On macOS, mark the file as downloaded from the internet, like a browser does, so
// Gatekeeper checks it before anything in it can run. Best effort elsewhere.
export function quarantine(path) {
  if (process.platform !== 'darwin') return false;
  try {
    const stamp = Math.floor(Date.now() / 1000).toString(16);
    execFileSync('/usr/bin/xattr', ['-w', 'com.apple.quarantine', `0083;${stamp};gmail-tidy-mcp;`, path]);
    return true;
  } catch {
    return false;
  }
}

// --- Attaching local files to drafts ------------------------------------------
// A draft is never sent, but a model steered by a malicious email could still try to
// put a private file (an SSH key, this server's own tokens) into a draft addressed to
// someone else, hoping you send it without looking. So only files under a few user
// folders can be attached, never hidden folders, and links are resolved first.

export const MAX_ATTACH_BYTES = 24 * 1024 * 1024; // Gmail's limit is 25 MB per message

export function attachDirs() {
  const custom = process.env.GMAIL_TIDY_ATTACH_DIRS;
  if (custom) return custom.split(':').filter(Boolean);
  return ['Downloads', 'Desktop', 'Documents'].map((d) => join(homedir(), d)).concat(DOWNLOADS);
}

const MIME = {
  '.pdf': 'application/pdf', '.txt': 'text/plain', '.csv': 'text/csv', '.md': 'text/markdown', '.html': 'text/html',
  '.json': 'application/json', '.xml': 'application/xml', '.zip': 'application/zip', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.doc': 'application/msword', '.xls': 'application/vnd.ms-excel', '.ppt': 'application/vnd.ms-powerpoint',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.ics': 'text/calendar', '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.mov': 'video/quicktime',
};

export function mimeType(filename) {
  return MIME[extname(filename).toLowerCase()] ?? 'application/octet-stream';
}

// Returns { filename, mimeType, bytes } or throws with the reason in plain words.
export function readAttachable(path, { dirs = attachDirs(), configDir } = {}) {
  const expanded = String(path).replace(/^~(?=\/|$)/, homedir());
  let real;
  try {
    real = realpathSync(expanded);
  } catch {
    throw new Error(`There is no file at ${path}.`);
  }
  const roots = dirs.map((d) => {
    try { return realpathSync(d); } catch { return null; }
  }).filter(Boolean);
  const root = roots.find((r) => real === r || real.startsWith(r + sep));
  if (!root) throw new Error(`${path} is outside the folders drafts can attach from (${dirs.join(', ')}).`);
  if (relative(root, real).split(sep).some((part) => part.startsWith('.'))) {
    throw new Error(`${path} is in a hidden folder or is a hidden file; those can't be attached.`);
  }
  if (configDir) {
    let conf = null;
    try { conf = realpathSync(configDir); } catch { /* not created yet */ }
    if (conf && (real === conf || real.startsWith(conf + sep))) throw new Error("This server's own files can't be attached.");
  }
  const info = statSync(real);
  if (!info.isFile()) throw new Error(`${path} is not a file.`);
  if (info.size > MAX_ATTACH_BYTES) throw new Error(`${path} is ${(info.size / 1048576).toFixed(1)} MB; Gmail takes up to 25 MB per email.`);
  return { filename: basename(real), mimeType: mimeType(real), bytes: readFileSync(real) };
}
