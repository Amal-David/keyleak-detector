const SEVERITY_ORDER = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SECRET_QUERY_KEYS = new Set([
  'access_token',
  'api_key',
  'apikey',
  'auth',
  'authorization',
  'client_secret',
  'code',
  'cookie',
  'key',
  'password',
  'refresh_token',
  'secret',
  'session',
  'token',
]);

export function normalizeSeverity(severity) {
  const value = String(severity || 'info').toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, value) ? value : 'info';
}

export function severityRank(severity) {
  return SEVERITY_ORDER[normalizeSeverity(severity)];
}

export function confidenceForSeverity(severity, source = '') {
  const normalized = normalizeSeverity(severity);
  if (normalized === 'critical' || normalized === 'high') return 0.9;
  if (normalized === 'medium') return 0.7;
  const sourceText = String(source || '').toLowerCase();
  if (sourceText.includes('url') || sourceText.includes('header')) return 0.65;
  return 0.55;
}

export function redactValue(value, keepStart = 12, keepEnd = 6) {
  if (value === undefined || value === null) return '';
  const text = String(value).trim();
  if (!text) return '';
  if (text.length <= 24) return text;
  return `${text.slice(0, keepStart)}...${text.slice(-keepEnd)}`;
}

export function redactSnippet(snippet, rawValue = '') {
  const text = String(snippet || '');
  const rawText = String(rawValue || '');
  if (!text) return '';
  if (rawText && text.includes(rawText)) {
    return text.split(rawText).join(redactValue(rawText));
  }
  return text;
}

export function redactUrl(url) {
  const text = String(url || '');
  if (!text) return '';
  return text.replace(/([?&])([^=&]+)=([^&#]+)/g, (match, separator, key, rawValue) => {
    if (!SECRET_QUERY_KEYS.has(String(key).toLowerCase())) return match;
    return `${separator}${key}=${redactValue(rawValue)}`;
  });
}

export function stableId(parts, prefix = 'finding') {
  const payload = parts.map(part => (part === undefined || part === null ? '' : String(part))).join('\n');
  let hash = 2166136261;
  for (let index = 0; index < payload.length; index += 1) {
    hash ^= payload.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `${prefix}_${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

export function normalizeFinding(raw) {
  const severity = normalizeSeverity(raw.severity);
  const source = raw.source || raw.evidence?.source || 'unknown';
  const rawValue = raw.raw_value ?? raw.value ?? raw.match ?? '';
  const redactedValue = raw.redacted_value || raw.evidence?.redacted_value || redactValue(rawValue);
  const requestUrl = redactUrl(raw.url || raw.request_url || raw.evidence?.request_url || '');
  const snippet = redactSnippet(raw.context || raw.snippet || raw.evidence?.snippet || '', rawValue);
  const detectorId = raw.detector_id || `runtime:${raw.type || 'unknown'}`;
  const category = raw.category || raw.pack || (String(detectorId).includes('.') ? String(detectorId).split('.')[0] : 'leak');

  const evidence = {
    source,
    snippet,
    line: raw.line ?? null,
    request_url: requestUrl,
    response_status: raw.status ?? raw.status_code ?? raw.evidence?.response_status ?? null,
    redacted_value: redactedValue,
  };

  const id = raw.id || stableId([
    raw.type || 'unknown',
    detectorId,
    source,
    redactedValue,
    evidence.line,
    requestUrl,
  ]);

  return {
    id,
    type: raw.type || 'unknown',
    severity,
    confidence: raw.confidence ?? confidenceForSeverity(severity, source),
    detector_id: detectorId,
    category,
    source,
    evidence,
    redacted_value: redactedValue,
    raw_value: rawValue ? String(rawValue).slice(0, 1000) : '',
    risk_reason: raw.risk_reason || raw.description || `${raw.type || 'Secret'} detected in ${source}.`,
    remediation: raw.remediation || raw.recommendation || 'Review this finding and remove exposed sensitive data.',
    references: raw.references || [],
    validation_status: raw.validation_status || 'lead',
    timestamp: raw.timestamp || Date.now(),
    content_type: raw.contentType || raw.content_type || '',
    url: requestUrl,
    capture_type: raw.capture_type || raw.captureType || '',
  };
}

export function summarizeFindings(findings) {
  const summary = {
    total_findings: findings.length,
    critical_severity: 0,
    high_severity: 0,
    medium_severity: 0,
    low_severity: 0,
    info_severity: 0,
  };

  for (const finding of findings) {
    const key = `${normalizeSeverity(finding.severity)}_severity`;
    summary[key] = (summary[key] || 0) + 1;
  }
  return summary;
}

export function verdictForFindings(findings) {
  const summary = summarizeFindings(findings);
  if (summary.critical_severity || summary.high_severity) {
    return {
      status: 'BLOCK_SHIP',
      label: 'BLOCK SHIP',
      reason: 'Critical or high-confidence exposures need fixing before release.',
    };
  }
  if (summary.medium_severity) {
    return {
      status: 'REVIEW',
      label: 'REVIEW',
      reason: 'Potential exposures or launch risks need human review.',
    };
  }
  return {
    status: 'SAFE_TO_SHIP',
    label: 'SAFE TO SHIP',
    reason: 'No medium, high, or critical findings were detected in the covered browser surfaces.',
  };
}

export function buildReport(target, findings, stats = {}, extra = {}) {
  const normalizedFindings = findings.map(finding => normalizeFinding(finding))
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
  const reportFindings = normalizedFindings.map((finding) => {
    const { raw_value: _rawValue, ...safeFinding } = finding;
    return safeFinding;
  });

  const packs = extra.packs || ['leak', 'appsec', 'access-control'];
  return {
    target: redactUrl(target || ''),
    scan_mode: 'extension-launch-gate',
    generated_at: new Date().toISOString(),
    verdict: verdictForFindings(reportFindings),
    summary: summarizeFindings(reportFindings),
    retest_command: target ? `keyleak scan ${redactUrl(target)}` : 'keyleak scan <url>',
    findings: reportFindings,
    coverage: coverageForStats(stats),
    packs,
    pack_summary: summarizeByCategory(reportFindings, packs),
    profile: 'launch-gate',
    ...extra,
  };
}

export function summarizeByCategory(findings, packs = []) {
  const summary = {};
  for (const pack of packs) {
    summary[pack] = {
      total_findings: 0,
      critical_severity: 0,
      high_severity: 0,
      medium_severity: 0,
      low_severity: 0,
      info_severity: 0,
    };
  }
  for (const finding of findings) {
    const category = finding.category || 'leak';
    if (!summary[category]) {
      summary[category] = {
        total_findings: 0,
        critical_severity: 0,
        high_severity: 0,
        medium_severity: 0,
        low_severity: 0,
        info_severity: 0,
      };
    }
    summary[category].total_findings += 1;
    const key = `${normalizeSeverity(finding.severity)}_severity`;
    summary[category][key] = (summary[category][key] || 0) + 1;
  }
  return summary;
}

export function coverageForStats(stats = {}) {
  const covered = [];
  if (stats.requests) covered.push('headers and URLs');
  if (stats.bodies) covered.push('fetch/XHR bodies');
  if (stats.externalScripts) covered.push('external scripts');
  if (stats.sourceMaps) covered.push('source maps');
  if (stats.scripts) covered.push('inline scripts');
  if (stats.dataAttrs) covered.push('data attributes');
  if (stats.metaTags) covered.push('meta tags');
  if (stats.storage) covered.push('browser storage');
  if (stats.libraries) covered.push('JS library versions');
  if (stats.websockets) covered.push('WebSocket messages');
  if (stats.eventStreams) covered.push('EventSource/SSE messages');
  if (stats.devtoolsBodies) covered.push('DevTools network bodies');

  return {
    level: covered.length >= 4 ? 'strong' : covered.length > 0 ? 'partial' : 'waiting',
    covered,
    note: covered.length
      ? 'Extension results are based on covered browser runtime surfaces; use full scan for attack surface checks.'
      : 'Browse or run a full local scan to collect launch-gate evidence.',
  };
}

export function formatMarkdownReport(report) {
  const lines = [
    `# KeyLeak Extension Report: ${report.verdict.label}`,
    '',
    `- Target: \`${report.target || 'unknown'}\``,
    `- Packs: \`${(report.packs || []).join(', ') || 'none'}\``,
    `- Generated: \`${report.generated_at}\``,
    `- Reason: ${report.verdict.reason}`,
    `- Re-test: \`${report.retest_command}\``,
    '',
    '## Coverage',
    report.coverage.covered.length ? report.coverage.covered.map(item => `- ${item}`).join('\n') : '- No browser surfaces covered yet.',
    '',
    '## Findings',
  ];

  if (!report.findings.length) {
    lines.push('No findings detected in covered browser surfaces.');
    return lines.join('\n');
  }

  for (const finding of report.findings) {
    lines.push(
      '',
      `### ${finding.severity.toUpperCase()}: ${finding.type}`,
      `- ID: \`${finding.id}\``,
      `- Detector: \`${finding.detector_id}\``,
      `- Pack: \`${finding.category || 'unknown'}\``,
      `- Source: \`${finding.source}\``,
      `- Evidence: \`${finding.evidence.redacted_value}\``,
      `- Why it matters: ${finding.risk_reason}`,
      `- Fix: ${finding.remediation}`,
      `- Validation: \`${finding.validation_status}\``,
    );
  }
  return lines.join('\n');
}

export function formatSarifReport(report) {
  const rules = new Map();
  const results = [];

  for (const finding of report.findings) {
    rules.set(finding.detector_id, {
      id: finding.detector_id,
      name: finding.type,
      shortDescription: { text: finding.type },
      fullDescription: { text: finding.risk_reason },
      help: { text: finding.remediation },
      properties: { category: finding.category || '' },
    });
    results.push({
      ruleId: finding.detector_id,
      level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'note',
      message: { text: finding.risk_reason },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.source },
            region: { startLine: finding.evidence.line || 1 },
          },
        },
      ],
      partialFingerprints: { findingId: finding.id },
      properties: { category: finding.category || '' },
    });
  }

  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'KeyLeak Detector Chrome Extension',
            informationUri: 'https://github.com/Amal-David/keyleak-detector',
            rules: Array.from(rules.values()),
          },
        },
        results,
      },
    ],
  }, null, 2);
}
