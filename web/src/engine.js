/** Local-only scanner boundary. No fetches, uploads, eval, or scanned-code execution. */

import { analyzeContent } from '../../extension/lib/analyzer.js';
import { COMPILED_PATTERNS, PATTERN_DEFINITIONS } from '../../extension/lib/patterns.js';
import { isCloudStorageSignedUrl, isAzureSasToken } from '../../extension/lib/false-positives.js';
import { buildReport, persistentSnapshot, stableId } from '../../extension/lib/reporting.js';
import { ArchiveError, readZipEntries } from './archive.js';

export const DEFAULT_LIMITS = Object.freeze({
  maxFileBytes: 2 * 1024 * 1024,
  maxInputBytes: 20 * 1024 * 1024,
  maxAnalysisBytes: 40 * 1024 * 1024,
  maxEntries: 500,
  maxFindings: 500,
  maxDurationMs: 20_000,
  maxCompressionRatio: 100,
});

const UNSUPPORTED_ARCHIVE = /\.(?:tar|tgz|gz|bz2|xz|7z|rar|zst|br|cab|iso|apk|jar|war|whl)$/i;
const BINARY_EXTENSION = /\.(?:png|jpe?g|gif|webp|ico|pdf|woff2?|ttf|otf|mp[34]|mov|avi|wav|ogg|exe|dll|so|dylib|elf|bin|macho|wasm|class|pyc|sqlite3?|db)$/i;
const MAX_REASONS = 80;
const BLOCK_FINDING_LIMIT = 50; // The shared analyzer's own fixed per-content limit.
const UTF8 = new TextEncoder();

function boundedLimits(overrides = {}) {
  return Object.fromEntries(Object.entries(DEFAULT_LIMITS).map(([key, maximum]) => {
    const value = overrides?.[key];
    return [key, Number.isFinite(value) && value >= 1
      ? Math.min(maximum, Math.floor(value)) : maximum];
  }));
}

/** Heuristically scrub labels while preserving useful ordinary path components. */
export function safeSourceName(value, index = 1) {
  const fallback = `Input ${index}`;
  if (typeof value !== 'string' || !value || value.length > 300
      || /[\u0000-\u001f\u007f<>@?#=]|[A-Za-z0-9_+\-]{20,}/.test(value)
      || /(?:^|[\/\s])(?:password|passwd|pwd|secret|token|api[_-]?key)[-:]/i.test(value)) return fallback;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)) {
    try {
      const url = new URL(value);
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password
          || url.search || url.hash || url.pathname.includes(':')) return fallback;
      return `${url.origin}${url.pathname}`;
    } catch (_error) {
      return fallback;
    }
  }
  if (/[:\\]|(?:^|\/)\.\.(?:\/|$)/.test(value)) return fallback;
  return value;
}

function magic(bytes, values) {
  return bytes.length >= values.length && values.every((value, index) => bytes[index] === value);
}

function isZip(bytes, name) {
  return /\.zip$/i.test(name) || magic(bytes, [0x50, 0x4b, 0x03, 0x04])
    || magic(bytes, [0x50, 0x4b, 0x05, 0x06]);
}

function unsupportedArchive(bytes, name) {
  return UNSUPPORTED_ARCHIVE.test(name) || magic(bytes, [0x1f, 0x8b])
    || magic(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
    || magic(bytes, [0x52, 0x61, 0x72, 0x21])
    || magic(bytes, [0x42, 0x5a, 0x68])
    || magic(bytes, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])
    || (bytes.length > 262 && new TextDecoder().decode(bytes.subarray(257, 262)) === 'ustar');
}

function binaryLike(bytes, name, type) {
  if (typeof type === 'string' && type !== 'image/svg+xml'
      && /^(?:(?:image|audio|video|font)\/|application\/(?:pdf|wasm|x-executable|x-sqlite3)(?:$|;))/i.test(type)) return true;
  if (BINARY_EXTENSION.test(name) || magic(bytes, [0x7f, 0x45, 0x4c, 0x46])
      || magic(bytes, [0x4d, 0x5a]) || magic(bytes, [0x00, 0x61, 0x73, 0x6d])) return true;
  if ([
    [0x25, 0x50, 0x44, 0x46], [0x89, 0x50, 0x4e, 0x47], [0xff, 0xd8, 0xff],
    [0x47, 0x49, 0x46, 0x38], [0x77, 0x4f, 0x46, 0x46], [0x77, 0x4f, 0x46, 0x32],
    [0x4f, 0x67, 0x67, 0x53], [0x66, 0x4c, 0x61, 0x43], [0x49, 0x44, 0x33],
    [0xfe, 0xed, 0xfa, 0xce], [0xce, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe],
  ].some(prefix => magic(bytes, prefix))) return true;
  let controls = 0;
  for (const value of bytes.subarray(0, 8192)) {
    if (value === 0) return true;
    if (value < 32 && ![9, 10, 12, 13].includes(value)) controls += 1;
  }
  return controls > Math.max(2, Math.min(bytes.length, 8192) * 0.01);
}

function patternCoverage() {
  const invalid = [];
  for (const rule of PATTERN_DEFINITIONS) {
    try {
      const regex = new RegExp(rule.pattern, rule.flags);
      if (!COMPILED_PATTERNS[rule.id] || !regex.global || regex.test('')) invalid.push(rule.id);
    } catch (_error) {
      invalid.push(rule.id);
    }
  }
  return { registered: PATTERN_DEFINITIONS.length, compiled: Object.keys(COMPILED_PATTERNS).length, invalid: invalid.length };
}

function appendShortOtpFindings(content, findings, check) {
  // The shared false-positive filter rejects every value shorter than ten
  // characters, including this rule's intended 4–8-character OTP captures.
  // Adapt this one rule locally; do not relax filtering for other detectors.
  const entry = COMPILED_PATTERNS.otp_in_response;
  if (!entry || findings.length >= BLOCK_FINDING_LIMIT) return;
  // Bound the canonical alternation so a numeric prefix can backtrack to its
  // alphanumeric branch instead of silently dropping a code such as 1234AB.
  const regex = new RegExp(`(?:${entry.pattern.source})(?![A-Za-z0-9])`, entry.pattern.flags);
  const seen = new Set(findings.filter(finding => finding.detector_id === entry.detector_id)
    .map(finding => finding.raw_value));
  let match;
  let inspected = 0;
  while (findings.length < BLOCK_FINDING_LIMIT && (match = regex.exec(content)) !== null) {
    if (++inspected % 64 === 0) check();
    const value = String(match[entry.capture_group || 1] || '').trim();
    if (!/^[A-Za-z0-9]{4,8}$/.test(value) || !/\d/.test(value)) continue;
    // Do not treat an eight-digit prefix of a longer field value as an OTP.
    const valueEnd = match.index + match[0].lastIndexOf(value) + value.length;
    if (/[A-Za-z0-9]/.test(content[valueEnd] || '') || seen.has(value)) continue;
    seen.add(value);
    findings.push({
      type: entry.finding_type || 'otp_in_response',
      detector_id: entry.detector_id,
      category: entry.category || entry.pack || 'appsec',
      severity: entry.severity,
      source: 'Local text input',
      raw_value: value,
      validation_status: 'lead',
      risk_reason: 'An OTP-shaped value appears in an OTP or verification-code field. This is an unverified pattern lead; source, fixture, or example text does not establish a live authentication exposure.',
      remediation: entry.remediation,
      references: entry.references || [],
    });
  }
}

function privacySafeFinding(finding, source, index) {
  // The extension's short-token and adjacent-context policy is intentionally not
  // reused for persisted web reports. Even a 20-character credential stays masked.
  const { raw_value: _raw, context: _context, snippet: _snippet, ...rest } = finding;
  return {
    ...rest,
    id: stableId([source, finding.detector_id, index], 'browser'),
    source,
    raw_value: '',
    redacted_value: '[redacted]',
    context: '',
    snippet: '',
    url: '',
    request_url: '',
    validation_status: 'lead',
    evidence: {
      source, snippet: '', line: null, request_url: '', response_status: null,
      redacted_value: '[redacted]', sample: '', raw_sample_available: false,
    },
  };
}

/**
 * Analyze user-selected inputs in-process. Run in scan-worker.js in the UI.
 * Each input is {name, content?: string, bytes?: ArrayBuffer|Uint8Array, type?}.
 * Limits can only be lowered. onProgress receives counts, never source content.
 */
export async function scanInputs(inputs, { onProgress, signal, limits: requestedLimits } = {}) {
  const limits = boundedLimits(requestedLimits);
  const started = performance.now();
  const findings = [];
  const reasons = [];
  const reasonKeys = new Set();
  const stats = { attempted: 0, completed: 0, skipped: 0, failed: 0, entries: 0,
    containers: 0, textFiles: 0, sourceMapSources: 0, inputBytes: 0, analysisBytes: 0 };
  const rules = patternCoverage();
  let stopped = false;
  let reasonsDropped = 0;

  function reason(code, message, source = '') {
    const key = `${code}:${source}`;
    if (reasonKeys.has(key)) return;
    reasonKeys.add(key);
    if (reasons.length < MAX_REASONS) reasons.push({ code, message, ...(source ? { source } : {}) });
    else reasonsDropped += 1;
  }

  function check() {
    if (signal?.aborted) throw new ArchiveError('cancelled', 'The scan was canceled before all selected content was analyzed.');
    if (performance.now() - started >= limits.maxDurationMs) {
      throw new ArchiveError('time_limit', 'The scan reached its elapsed-time limit; some content remains unanalyzed.');
    }
  }

  function progress() {
    if (typeof onProgress === 'function') onProgress({ ...stats, findings: findings.length });
  }

  function skip(code, message, source) {
    stats.skipped += 1;
    reason(code, message, source);
  }

  function stop(code, message, source) {
    skip(code, message, source);
    stopped = true;
  }

  async function visit(input, { archiveMember = false, sourceDepth = 0, imported = true } = {}) {
    if (stopped) return;
    check();
    stats.attempted += 1;
    if (stats.entries >= limits.maxEntries) {
      stop('entry_limit', 'The combined file and archive-entry limit was reached.');
      return;
    }
    stats.entries += 1;
    const source = safeSourceName(input?.name, stats.entries);
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || (input.content !== undefined && input.bytes !== undefined)) {
      skip('invalid_input', 'An input did not have one supported content representation.', source);
      return;
    }
    const name = typeof input.name === 'string' ? input.name : '';
    let bytes;
    if (typeof input.content === 'string') {
      if (input.content.length > limits.maxFileBytes) {
        skip('file_byte_limit', 'A text input exceeds the per-file byte limit.', source);
        return;
      }
      bytes = UTF8.encode(input.content);
    } else if (input.bytes instanceof Uint8Array) {
      bytes = input.bytes;
    } else if (input.bytes instanceof ArrayBuffer) {
      bytes = new Uint8Array(input.bytes);
    } else {
      skip('invalid_input', 'An input did not contain supported text or bytes.', source);
      return;
    }
    if (imported) {
      if (bytes.byteLength > limits.maxInputBytes - stats.inputBytes) {
        stop('input_byte_limit', 'The aggregate imported-byte limit was reached.', source);
        return;
      }
      stats.inputBytes += bytes.byteLength;
    }
    if (isZip(bytes, name)) {
      if (archiveMember || sourceDepth) {
        skip('nested_archive', 'Nested archives are not expanded. Scan their contents separately.', source);
        return;
      }
      stats.containers += 1;
      try {
        for await (const entry of readZipEntries(bytes, {
          signal, checkCancelled: check,
          limits: {
            maxArchiveBytes: limits.maxInputBytes,
            maxEntries: limits.maxEntries - stats.entries,
            maxEntryBytes: limits.maxFileBytes,
            maxTotalBytes: limits.maxAnalysisBytes - stats.analysisBytes,
            maxCompressionRatio: limits.maxCompressionRatio,
          },
        })) {
          if (stopped) break;
          if (entry.directory) {
            stats.entries += 1;
            continue;
          }
          await visit({ name: `${source}!/${entry.name}`, bytes: entry.bytes }, { archiveMember: true, imported: false });
          progress();
        }
        stats.completed += 1;
      } catch (error) {
        if (error instanceof ArchiveError && ['cancelled', 'time_limit'].includes(error.code)) throw error;
        stats.failed += 1;
        reason(error instanceof ArchiveError ? error.code : 'archive_failed',
          error instanceof ArchiveError ? error.message : 'The ZIP could not be analyzed.', source);
      }
      return;
    }
    if (unsupportedArchive(bytes, name)) {
      skip('unsupported_archive', 'This archive or compressed-file format is not supported; use ordinary ZIP or uncompressed text files.', source);
      return;
    }
    if (bytes.byteLength > limits.maxFileBytes) {
      skip('file_byte_limit', 'A file exceeds the per-file byte limit.', source);
      return;
    }
    if (binaryLike(bytes, name, input.type)) {
      skip('unsupported_binary', 'Binary files are not scanned by the browser text engine.', source);
      return;
    }
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (_error) {
      skip('unsupported_encoding', 'A file is not valid UTF-8 text; its content was not scanned.', source);
      return;
    }
    if (bytes.byteLength > limits.maxAnalysisBytes - stats.analysisBytes) {
      stop('analysis_byte_limit', 'The aggregate analysis and expanded-content byte limit was reached.', source);
      return;
    }
    if (rules.invalid || !rules.compiled) {
      skip('invalid_rules', 'The detector bundle is incomplete or invalid; analysis cannot establish clean coverage.', source);
      return;
    }
    if (isCloudStorageSignedUrl('', 'Local text input', text) || isAzureSasToken(text)) {
      skip('analyzer_filter', 'The shared analyzer excludes this cloud-storage or signed-URL content block; it was not analyzed.', source);
      return;
    }
    stats.analysisBytes += bytes.byteLength;
    let matches;
    try {
      // User-controlled filenames/URLs must not trigger the extension's domain,
      // vendor-script, browser-token, or authentication-header skip heuristics.
      matches = analyzeContent(text, 'Local text input', {});
      appendShortOtpFindings(text, matches, check);
    } catch (_error) {
      stats.failed += 1;
      reason('analysis_failed', 'The text analyzer could not complete this file.', source);
      return;
    }
    check();
    if (matches.length >= BLOCK_FINDING_LIMIT) {
      reason('file_finding_limit', 'The shared detector reached its per-file finding limit; additional matches may be unreported.', source);
    }
    for (const finding of matches) {
      if (findings.length >= limits.maxFindings) {
        reason('finding_limit', 'The scan reached its overall finding limit; additional content remains unanalyzed.');
        stopped = true;
        break;
      }
      findings.push(privacySafeFinding(finding, source, findings.length));
    }
    stats.completed += 1;
    stats.textFiles += 1;
    if (stopped) return;

    // Source maps are parsed strictly as JSON; source URLs are never fetched.
    if (/\.map$/i.test(name) || (/^\s*\{/.test(text) && text.includes('"sourcesContent"'))) {
      let map;
      try {
        map = JSON.parse(text);
      } catch (_error) {
        reason('invalid_sourcemap', 'The source-map JSON could not be decoded; embedded sources were not reconstructed.', source);
        return;
      }
      if (!map || typeof map !== 'object' || map.version !== 3) {
        reason('unsupported_sourcemap', 'Only version 3 source maps with embedded sourcesContent are reconstructed.', source);
        return;
      }
      if (map.sections) reason('indexed_sourcemap', 'Indexed source-map sections are not reconstructed in this browser version.', source);
      if (!Array.isArray(map.sourcesContent)) {
        reason('missing_sourcemap_sources', 'This source map has no embedded sourcesContent; external source URLs were not fetched.', source);
        return;
      }
      if (Array.isArray(map.sources) && map.sources.length > map.sourcesContent.length) {
        reason('missing_sourcemap_source', 'Some source-map entries do not include their original text.', source);
      }
      if (sourceDepth >= 1) {
        reason('sourcemap_depth_limit', 'Nested source-map reconstruction reached its depth limit.', source);
        return;
      }
      for (let index = 0; index < map.sourcesContent.length; index += 1) {
        if (stopped) break;
        if (typeof map.sourcesContent[index] !== 'string') {
          reason('missing_sourcemap_source', 'Some source-map entries do not include their original text.', source);
          continue;
        }
        stats.sourceMapSources += 1;
        const originalName = safeSourceName(map.sources?.[index], index + 1);
        await visit({ name: `${source}!/${originalName}`, content: map.sourcesContent[index] },
          { sourceDepth: sourceDepth + 1, archiveMember, imported: false });
      }
    }
  }

  if (!Array.isArray(inputs) || !inputs.length) {
    reason('no_inputs', 'No files or text were supplied for analysis.');
    inputs = [];
  }
  try {
    for (const input of inputs) {
      if (stopped) break;
      await visit(input);
      progress();
      // Give progress and cancellation a turn between bounded units of work.
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    check();
  } catch (error) {
    stopped = true;
    reason(error instanceof ArchiveError ? error.code : 'scan_failed',
      error instanceof ArchiveError ? error.message : 'Local analysis stopped unexpectedly; coverage is incomplete.');
  }
  if (!stats.textFiles) reason('no_text_scanned', 'No supported text inputs were fully analyzed.');
  if (reasonsDropped) reasons.push({ code: 'additional_gaps', message: `${reasonsDropped} additional coverage gaps were omitted from this bounded report.` });
  const incomplete = stopped || reasons.length > 0;
  const coverage = {
    status: incomplete ? 'partial' : 'complete',
    level: incomplete ? 'partial' : 'bounded',
    unit: 'files and archive containers',
    attempted: stats.attempted, completed: stats.completed, skipped: stats.skipped, failed: stats.failed,
    reasons,
    covered: stats.textFiles ? ['selected UTF-8 text and embedded source-map sources'] : [],
    note: 'Pattern analysis of selected content only. No live credential validation, native binary analysis, runtime execution, or complete-site assessment.',
    input_bytes: stats.inputBytes, analyzed_bytes: stats.analysisBytes,
    text_files: stats.textFiles, archive_containers: stats.containers,
    source_map_sources: stats.sourceMapSources,
  };
  const report = buildReport('Selected browser inputs', findings, {}, {
    schema_version: 1,
    scan_mode: 'browser-local',
    profile: 'bounded-local-text',
    retest_command: '',
    coverage,
    coverage_incomplete: incomplete,
    limits,
    detector_bundle: rules,
    capabilities: {
      execution: 'browser-worker',
      network_requests: false,
      code_execution: false,
      live_validation: false,
      pattern_adapters: ['appsec.otp_in_response: bounded short-code capture'],
      formats: ['UTF-8 text', 'ZIP (stored/deflate)', 'source maps with sourcesContent'],
      unsupported: ['native binaries', 'nested archives', 'ZIP64', 'encrypted ZIP', 'non-UTF-8 text', 'Python AST checks', 'native tools'],
    },
    privacy: { raw_values_stored: false, source_snippets_stored: false, input_content_stored: false,
      source_names: 'Heuristically scrubbed filenames and paths; project metadata may remain.' },
    elapsed_ms: Math.round(performance.now() - started),
  });
  if (!findings.length) report.verdict = incomplete
    ? { status: 'INCOMPLETE', label: 'Incomplete scan', reason: 'Some selected content could not be analyzed. No clean result can be established.' }
    : { status: 'NO_FINDINGS', label: 'No findings in analyzed text', reason: 'No matches were found by the available text detectors. This does not establish that a project or site is secure.' };
  else report.verdict = {
    status: 'REVIEW',
    label: incomplete ? 'Findings in an incomplete scan' : 'Findings to review',
    reason: 'Potential exposures were found in the analyzed text. Pattern matches are unverified; no live credential validation was performed.'
      + (incomplete ? ' Coverage is incomplete; review the reported gaps.' : ''),
  };
  return persistentSnapshot(report);
}
