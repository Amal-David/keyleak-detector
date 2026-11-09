/** Bounded ZIP reader. Entries are bytes, never extracted to disk or executed. */

export const ARCHIVE_LIMITS = Object.freeze({
  maxArchiveBytes: 20 * 1024 * 1024,
  maxEntries: 500,
  maxEntryBytes: 2 * 1024 * 1024,
  maxTotalBytes: 40 * 1024 * 1024,
  maxCompressionRatio: 100,
});

export class ArchiveError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ArchiveError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new ArchiveError(code, message);
}

function boundedLimits(overrides = {}) {
  return Object.fromEntries(Object.entries(ARCHIVE_LIMITS).map(([key, maximum]) => {
    const value = overrides[key];
    return [key, Number.isFinite(value) && value >= 0
      ? Math.min(maximum, Math.floor(value)) : maximum];
  }));
}

function asBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  fail('invalid_archive', 'The ZIP input is not a byte buffer.');
}

function range(start, length, end) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length)
      || start < 0 || length < 0 || start > end - length) {
    fail('invalid_archive', 'The ZIP contains an out-of-bounds record.');
  }
}

function rejectZip64Extra(bytes, offset, length) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = offset + length;
  range(offset, length, bytes.length);
  while (offset < end) {
    range(offset, 4, end);
    const id = view.getUint16(offset, true);
    const size = view.getUint16(offset + 2, true);
    if (id === 0x0001) fail('unsupported_zip64', 'ZIP64 archives are not supported.');
    offset += 4;
    range(offset, size, end);
    offset += size;
  }
}

function decodeName(bytes, utf8) {
  if (!bytes.length || bytes.length > 1024) {
    fail('unsafe_archive_path', 'A ZIP entry has an empty or oversized path.');
  }
  if (!utf8 && bytes.some(value => value > 0x7f)) {
    fail('unsupported_zip_encoding', 'Legacy non-ASCII ZIP paths are not supported.');
  }
  let name;
  try {
    name = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (_error) {
    fail('unsupported_zip_encoding', 'A ZIP path is not valid UTF-8.');
  }
  const segments = name.replace(/\/$/, '').split('/');
  if (/^[\/\\]|^[A-Za-z]:|[\\\u0000-\u001f\u007f]/.test(name)
      || segments.some(part => !part || part === '.' || part === '..')) {
    fail('unsafe_archive_path', 'Absolute paths, traversal, and unsafe ZIP paths are refused.');
  }
  return name;
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function inspectZip(bytes, limits, check) {
  if (bytes.length > limits.maxArchiveBytes) {
    fail('archive_input_limit', 'The ZIP exceeds the compressed-input byte limit.');
  }
  if (bytes.length < 22) fail('invalid_archive', 'The ZIP end record is missing.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const first = view.getUint32(0, true);
  if (first !== 0x04034b50 && first !== 0x06054b50) {
    fail('unsupported_archive', 'Only ordinary ZIP files without an executable prefix are supported.');
  }
  let eocd = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50
        && offset + 22 + view.getUint16(offset + 20, true) === bytes.length) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0) fail('invalid_archive', 'The ZIP end record is invalid or truncated.');
  const entries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (entries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff
      || (eocd >= 20 && view.getUint32(eocd - 20, true) === 0x07064b50)) {
    fail('unsupported_zip64', 'ZIP64 archives are not supported.');
  }
  if (view.getUint16(eocd + 4, true) || view.getUint16(eocd + 6, true)
      || view.getUint16(eocd + 8, true) !== entries) {
    fail('unsupported_multidisk', 'Multi-disk ZIP archives are not supported.');
  }
  if (entries > limits.maxEntries) fail('archive_entry_limit', 'The ZIP exceeds the entry-count limit.');
  range(centralOffset, centralSize, eocd);
  if (centralOffset + centralSize !== eocd) {
    fail('invalid_archive', 'The ZIP central directory is not contiguous with its end record.');
  }
  const records = [];
  const names = new Set();
  let cursor = centralOffset;
  let totalBytes = 0;
  for (let index = 0; index < entries; index += 1) {
    check();
    range(cursor, 46, eocd);
    if (view.getUint32(cursor, true) !== 0x02014b50) {
      fail('invalid_archive', 'The ZIP central directory contains an invalid record.');
    }
    const flags = view.getUint16(cursor + 8, true);
    const method = view.getUint16(cursor + 10, true);
    const crc = view.getUint32(cursor + 16, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const size = view.getUint32(cursor + 24, true);
    const nameSize = view.getUint16(cursor + 28, true);
    const extraSize = view.getUint16(cursor + 30, true);
    const commentSize = view.getUint16(cursor + 32, true);
    const external = view.getUint32(cursor + 38, true);
    const localOffset = view.getUint32(cursor + 42, true);
    if (flags & 0x0041) fail('encrypted_archive', 'Encrypted ZIP entries are not supported.');
    if (flags & ~0x080e) fail('unsupported_zip_flags', 'A ZIP entry uses unsupported flags.');
    if (method !== 0 && method !== 8) {
      fail('unsupported_compression', 'Only stored and deflated ZIP entries are supported.');
    }
    if (view.getUint16(cursor + 34, true) !== 0) {
      fail('unsupported_multidisk', 'Multi-disk ZIP entries are not supported.');
    }
    if ([compressedSize, size, localOffset].includes(0xffffffff)) {
      fail('unsupported_zip64', 'ZIP64 archives are not supported.');
    }
    range(cursor + 46, nameSize + extraSize + commentSize, eocd);
    const rawName = bytes.subarray(cursor + 46, cursor + 46 + nameSize);
    const name = decodeName(rawName, Boolean(flags & 0x0800));
    if (names.has(name)) fail('duplicate_archive_path', 'Duplicate ZIP paths are refused.');
    names.add(name);
    rejectZip64Extra(bytes, cursor + 46 + nameSize, extraSize);
    const unixType = (external >>> 16) & 0xf000;
    if (unixType === 0xa000) fail('archive_symlink', 'Symbolic links inside ZIP files are refused.');
    if (unixType && unixType !== 0x8000 && unixType !== 0x4000) {
      fail('unsupported_archive_entry', 'Non-regular ZIP entries are refused.');
    }
    const directory = name.endsWith('/') || Boolean(external & 0x10) || unixType === 0x4000;
    if (directory && size !== 0) fail('invalid_archive', 'A ZIP directory contains unexpected data.');
    if (size > limits.maxEntryBytes) fail('archive_file_limit', 'A ZIP member exceeds the per-file byte limit.');
    totalBytes += size;
    if (totalBytes > limits.maxTotalBytes) {
      fail('archive_total_limit', 'The ZIP exceeds the expanded-byte limit.');
    }
    if (size > Math.max(1, compressedSize) * limits.maxCompressionRatio) {
      fail('archive_ratio_limit', 'A ZIP member exceeds the compression-ratio limit.');
    }
    if (method === 0 && compressedSize !== size) {
      fail('invalid_archive', 'A stored ZIP member has inconsistent sizes.');
    }
    range(localOffset, 30, centralOffset);
    if (view.getUint32(localOffset, true) !== 0x04034b50
        || view.getUint16(localOffset + 6, true) !== flags
        || view.getUint16(localOffset + 8, true) !== method) {
      fail('invalid_archive', 'The ZIP local header disagrees with the central directory.');
    }
    const localNameSize = view.getUint16(localOffset + 26, true);
    const localExtraSize = view.getUint16(localOffset + 28, true);
    range(localOffset + 30, localNameSize + localExtraSize, centralOffset);
    if (!sameBytes(rawName, bytes.subarray(localOffset + 30, localOffset + 30 + localNameSize))) {
      fail('invalid_archive', 'ZIP local and central paths do not match.');
    }
    rejectZip64Extra(bytes, localOffset + 30 + localNameSize, localExtraSize);
    const dataOffset = localOffset + 30 + localNameSize + localExtraSize;
    range(dataOffset, compressedSize, centralOffset);
    let localEnd = dataOffset + compressedSize;
    const expected = [crc, compressedSize, size];
    for (let field = 0; field < 3; field += 1) {
      const actual = view.getUint32(localOffset + 14 + field * 4, true);
      if (actual !== expected[field] && (!(flags & 8) || actual !== 0)) {
        fail('invalid_archive', 'ZIP local and central checksums or sizes do not match.');
      }
    }
    if (flags & 8) {
      range(localEnd, 12, centralOffset);
      if (view.getUint32(localEnd, true) === 0x08074b50) localEnd += 4;
      range(localEnd, 12, centralOffset);
      if (expected.some((value, field) => view.getUint32(localEnd + field * 4, true) !== value)) {
        fail('invalid_archive', 'The ZIP data descriptor is invalid.');
      }
      localEnd += 12;
    }
    records.push({ name, directory, size, compressedSize, crc, method, dataOffset, localOffset, localEnd });
    cursor += 46 + nameSize + extraSize + commentSize;
  }
  if (cursor !== eocd) fail('invalid_archive', 'The ZIP directory length or entry count is inconsistent.');
  const byOffset = [...records].sort((a, b) => a.localOffset - b.localOffset);
  let coveredEnd = 0;
  for (const record of byOffset) {
    if (record.localOffset > coveredEnd) {
      fail('unscanned_archive_data', 'The ZIP contains unreferenced or padded local data that cannot be fully inventoried.');
    }
    if (record.localOffset < coveredEnd) {
      fail('overlapping_archive_entries', 'Overlapping ZIP entries are refused.');
    }
    coveredEnd = record.localEnd;
  }
  if (coveredEnd !== centralOffset) {
    fail('unscanned_archive_data', 'The ZIP contains unreferenced or padded local data that cannot be fully inventoried.');
  }
  return records;
}

const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

async function inflate(bytes, expectedSize, check, signal) {
  let decompressor;
  try {
    decompressor = new DecompressionStream('deflate-raw');
  } catch (_error) {
    fail('decompression_unavailable', 'This browser cannot decompress deflated ZIP members. Try unzipped files.');
  }
  const reader = new Blob([bytes]).stream().pipeThrough(decompressor).getReader();
  const cancel = () => { reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      check();
      const result = await reader.read();
      check();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > expectedSize) {
        cancel();
        fail('archive_size_mismatch', 'A ZIP member expanded beyond its declared size.');
      }
      chunks.push(result.value);
    }
  } catch (error) {
    cancel();
    if (error instanceof ArchiveError) throw error;
    fail('invalid_archive', 'A deflated ZIP member is invalid or truncated.');
  } finally {
    signal?.removeEventListener('abort', cancel);
  }
  if (size !== expectedSize) fail('archive_size_mismatch', 'A ZIP member expanded to an unexpected size.');
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

/** Iterate validated bytes one entry at a time; no archive member is executed. */
export async function* readZipEntries(input, { limits: overrides, signal, checkCancelled } = {}) {
  const bytes = asBytes(input);
  const limits = boundedLimits(overrides);
  const check = () => {
    if (signal?.aborted) fail('cancelled', 'Archive analysis was canceled.');
    checkCancelled?.();
  };
  check();
  const records = inspectZip(bytes, limits, check);
  for (const record of records) {
    check();
    const compressed = bytes.subarray(record.dataOffset, record.dataOffset + record.compressedSize);
    const output = record.method === 0 ? compressed
      : await inflate(compressed, record.size, check, signal);
    check();
    if (crc32(output) !== record.crc) fail('archive_crc_mismatch', 'A ZIP member failed its checksum check.');
    yield { name: record.name, bytes: output, directory: record.directory, compressedBytes: record.compressedSize };
  }
}
