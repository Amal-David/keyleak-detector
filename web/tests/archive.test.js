import assert from 'node:assert/strict';
import test from 'node:test';
import { deflateRawSync } from 'node:zlib';
import { readZipEntries, ArchiveError } from '../src/archive.js';
import { scanInputs } from '../src/engine.js';

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Build synthetic ZIP records in memory; no archive-writing dependency or target files.
function zip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const localName = Buffer.from(entry.localName ?? entry.name);
    const data = Buffer.from(entry.content ?? 'A small local text file.');
    const method = entry.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(data) : data;
    const size = entry.size ?? data.length;
    const crc = entry.crc ?? crc32(data);
    const flags = entry.flags ?? (entry.descriptor ? 8 : 0);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(flags, 6);
    header.writeUInt16LE(method, 8);
    if (!(flags & 8)) {
      header.writeUInt32LE(crc, 14);
      header.writeUInt32LE(compressed.length, 18);
      header.writeUInt32LE(size, 22);
    }
    header.writeUInt16LE(localName.length, 26);
    const descriptor = entry.descriptor ? Buffer.alloc(16) : Buffer.alloc(0);
    if (entry.descriptor) {
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(crc, 4);
      descriptor.writeUInt32LE(compressed.length, 8);
      descriptor.writeUInt32LE(size, 12);
    }
    const local = Buffer.concat([header, localName, compressed, descriptor]);
    locals.push(local);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE((3 << 8) | 20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(flags, 8);
    record.writeUInt16LE(method, 10);
    record.writeUInt32LE(crc, 16);
    record.writeUInt32LE(compressed.length, 20);
    record.writeUInt32LE(size, 24);
    record.writeUInt16LE(name.length, 28);
    record.writeUInt32LE((entry.external ?? (0x81a4 << 16)) >>> 0, 38);
    record.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([record, name]));
    offset += local.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

async function collect(bytes, options) {
  const entries = [];
  for await (const entry of readZipEntries(bytes, options)) entries.push(entry);
  return entries;
}

async function rejects(bytes, code, options) {
  await assert.rejects(() => collect(bytes, options), error => error instanceof ArchiveError && error.code === code);
}

test('reads stored and deflated UTF-8 members, including data descriptors', async () => {
  const entries = await collect(zip([
    { name: 'plain.txt', content: 'Stored content' },
    { name: 'src/app.js', content: 'const message = "deflated local content";', method: 8, descriptor: true },
    { name: 'தமிழ்.txt', content: 'UTF-8 name', flags: 0x800 },
  ]));
  assert.equal(entries.length, 3);
  assert.equal(new TextDecoder().decode(entries[0].bytes), 'Stored content');
  assert.equal(new TextDecoder().decode(entries[1].bytes), 'const message = "deflated local content";');
  assert.equal(entries[2].name, 'தமிழ்.txt');
});

test('rejects traversal, absolute paths, backslashes, duplicate entries, and symlinks', async () => {
  for (const name of ['../outside.env', '/outside.env', 'C:/outside.env', 'a\\outside.env', 'a/../../outside.env']) {
    await rejects(zip([{ name }]), 'unsafe_archive_path');
  }
  await rejects(zip([{ name: 'same.env' }, { name: 'same.env' }]), 'duplicate_archive_path');
  await rejects(zip([{ name: 'link', external: (0xa1ff << 16) >>> 0 }]), 'archive_symlink');
});

test('rejects encrypted, ZIP64, unsupported methods, and mismatched local names', async () => {
  await rejects(zip([{ name: 'secret.env', flags: 1 }]), 'encrypted_archive');
  const large = zip([]);
  large.writeUInt16LE(0xffff, large.length - 12);
  await rejects(large, 'unsupported_zip64');
  await rejects(zip([{ name: 'text.txt', method: 99 }]), 'unsupported_compression');
  await rejects(zip([{ name: 'safe.txt', localName: 'evil.txt' }]), 'invalid_archive');
});

test('checks declared and actual byte bounds, expansion ratio, and checksums', async () => {
  await rejects(zip([{ name: 'bomb.txt', content: 'a'.repeat(10_000), method: 8 }]), 'archive_ratio_limit');
  await rejects(zip([{ name: 'x.txt', content: 'longer than declared', method: 8, size: 3 }]), 'archive_size_mismatch');
  await rejects(zip([{ name: 'x.txt', crc: 123 }]), 'archive_crc_mismatch');
  await rejects(zip([{ name: 'x.txt' }]), 'archive_file_limit', { limits: { maxEntryBytes: 2 } });
  await rejects(zip([{ name: 'x.txt' }]), 'archive_total_limit', { limits: { maxTotalBytes: 2 } });
  await rejects(zip([{ name: 'x.txt' }, { name: 'y.txt' }]), 'archive_entry_limit', { limits: { maxEntries: 1 } });
  const valid = zip([{ name: 'x.txt' }]);
  await rejects(valid.subarray(0, valid.length - 1), 'invalid_archive');
});

test('unreferenced deleted local entries cannot yield a clean archive scan', async () => {
  const original = zip([{ name: 'safe.txt', content: 'Nothing sensitive.' },
    { name: 'deleted.env', content: 'sk-proj-B3x7M2s9H5r8V4d6N1q0C3k7Z8t2W9p4' }]);
  const end = Buffer.from(original.subarray(-22));
  const directoryOffset = end.readUInt32LE(16);
  const firstRecordLength = 46 + Buffer.byteLength('safe.txt');
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(firstRecordLength, 12);
  const hiddenEntry = Buffer.concat([original.subarray(0, directoryOffset + firstRecordLength), end]);
  await rejects(hiddenEntry, 'unscanned_archive_data');
  const report = await scanInputs([{ name: 'updated.zip', bytes: hiddenEntry }]);
  assert.equal(report.verdict.status, 'INCOMPLETE');
  assert(report.coverage.reasons.some(reason => reason.code === 'unscanned_archive_data'));
});

test('unsupported deflate runtime reports a gap without fallback network dependencies', async () => {
  const old = globalThis.DecompressionStream;
  globalThis.DecompressionStream = class { constructor() { throw new Error('unsupported'); } };
  try {
    await rejects(zip([{ name: 'x.txt', method: 8 }]), 'decompression_unavailable');
  } finally {
    globalThis.DecompressionStream = old;
  }
});

test('ZIP engine integration redacts findings and records nested archive gaps', async () => {
  const secret = 'sk-proj-V8r4Q9m2B6k1H7s3D5p0N8x4C2t6W9z1';
  const bytes = zip([{ name: 'src/config.env', content: secret, method: 8 },
    { name: 'nested.zip', content: zip([{ name: 'x.txt' }]) }]);
  const report = await scanInputs([{ name: 'source.zip', bytes }]);
  assert(report.findings.some(item => item.type === 'openai_api_key'));
  assert(!JSON.stringify(report).includes(secret));
  assert(report.coverage.reasons.some(reason => reason.code === 'nested_archive'));
  assert.equal(report.coverage.status, 'partial');
});

test('canceled archive processing rejects before reading entries', async () => {
  const controller = new AbortController();
  controller.abort();
  await rejects(zip([{ name: 'x.txt' }]), 'cancelled', { signal: controller.signal });
});
