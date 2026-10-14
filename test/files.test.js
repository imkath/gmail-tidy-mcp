import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync, deflateRawSync } from 'node:zlib';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isText, readableText, safeName, saveFile, unzip } from '../src/files.js';

// Minimal zip writer for the tests: one deflated entry, sizes in the central directory.
function makeZip(name, content) {
  const data = Buffer.from(content);
  const comp = deflateRawSync(data);
  const n = Buffer.from(name);
  const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(8, 8);
  local.writeUInt32LE(comp.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(n.length, 26);
  const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(8, 10);
  central.writeUInt32LE(comp.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(n.length, 28);
  central.writeUInt32LE(0, 42);
  const cdStart = local.length + n.length + comp.length;
  const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length + n.length, 12); eocd.writeUInt32LE(cdStart, 16);
  return Buffer.concat([local, n, comp, central, n, eocd]);
}

const DMARC = '<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name></report_metadata></feedback>';

test('reads a zipped DMARC report as text', () => {
  assert.equal(unzip(makeZip('google.com!example.cl.xml', DMARC))[0].data.toString(), DMARC);
  assert.match(readableText('report.zip', 'application/zip', makeZip('r.xml', DMARC)), /org_name>google\.com/);
});

test('reads a gzipped DMARC report as text', () => {
  assert.equal(readableText('report.xml.gz', 'application/gzip', gzipSync(DMARC)), DMARC);
});

test('a PDF is not shown as text', () => {
  assert.equal(readableText('factura.pdf', 'application/pdf', Buffer.from('%PDF-1.7')), null);
  assert.ok(isText('datos.csv'));
  assert.ok(!isText('foto.jpg', 'image/jpeg'));
});

test('a file name from the sender cannot escape the downloads folder', () => {
  assert.equal(safeName('../../.ssh/authorized_keys'), 'authorized_keys');
  assert.equal(safeName('..\\..\\Windows\\evil.exe'), 'evil.exe');
  assert.equal(safeName('.bashrc'), 'bashrc');
  assert.equal(safeName(''), 'attachment');
});

test('saving never overwrites an existing file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gmail-tidy-'));
  saveFile(dir, 'factura.pdf', Buffer.from('one'));
  const second = saveFile(dir, 'factura.pdf', Buffer.from('two'));
  assert.ok(second.endsWith('factura (2).pdf'));
  assert.deepEqual(readdirSync(dir).sort(), ['factura (2).pdf', 'factura.pdf']);
  assert.equal(readFileSync(join(dir, 'factura.pdf'), 'utf8'), 'one');
});
