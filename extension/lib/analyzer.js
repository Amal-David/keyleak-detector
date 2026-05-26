/**
 * Content analyzer for KeyLeak Detector.
 * Scans text content for secrets using compiled regex patterns.
 */

import { COMPILED_PATTERNS } from './patterns.js';
import { isFalsePositive, isVendorScript, isCloudStorageSignedUrl, isAzureSasToken, isBrowserInternal, isInfraHeader, isOwnAuthHeader, isBrowserServiceToken, isFirstPartyDomain } from './false-positives.js';
import { normalizeFinding, redactSnippet } from './reporting.js';

/**
 * Analyze text content for potential secrets.
 * @param {string} content - The text to scan
 * @param {string} source - Where the content came from (e.g. 'Response Body', 'Request Header')
 * @returns {Array<Object>} Array of findings
 */
export function analyzeContent(content, source = '', meta = {}) {
  const findings = [];
  if (!content || typeof content !== 'string' || content.length < 10) return findings;

  // Skip obviously non-secret content types
  if (content.length > 5 * 1024 * 1024) return findings; // >5MB, skip

  // Skip first-party domains (Google on google.com, AWS on aws.amazon.com, etc.)
  if (isFirstPartyDomain(meta.url || '')) return findings;

  // Skip browser-internal URLs (chrome-extension://, devtools://, etc.)
  if (isBrowserInternal(source) || isBrowserInternal(meta.url || '')) return findings;

  // Skip user's own auth headers (Authorization: Bearer, Cookie)
  if (isOwnAuthHeader(source)) return findings;

  // Skip browser-internal service tokens (Translate, reCAPTCHA, Firebase Auth, etc.)
  if (isBrowserServiceToken(source)) return findings;

  // Skip infrastructure response headers (x-amz-cf-id, cf-ray, x-request-id, etc.)
  if (isInfraHeader(source)) return findings;

  // Skip known third-party vendor scripts (Google Analytics, PostHog, etc.)
  if (isVendorScript(source) || isVendorScript(meta.url || '')) return findings;

  // Skip cloud storage signed/pre-signed URLs (AWS S3, GCS, Azure, R2, etc.)
  if (isCloudStorageSignedUrl('', source, content) || isAzureSasToken(content)) return findings;

  const seen = new Set(); // deduplicate by value

  for (const [name, entry] of Object.entries(COMPILED_PATTERNS)) {
    // Clone regex to reset lastIndex
    const regex = new RegExp(entry.pattern.source, entry.pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      // Extract the captured group or full match
      const captureIndex = entry.capture_group || 0;
      const value = (match[captureIndex] || match[1] || match[0]).trim();

      // Skip duplicates within this content block
      const dedupeKey = `${name}:${value}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      // Skip false positives
      if (entry.min_match_length && value.length < entry.min_match_length) continue;
      if (isFalsePositive(value)) continue;

      // Get a snippet of surrounding context (up to 100 chars each side)
      const start = Math.max(0, match.index - 60);
      const end = Math.min(content.length, match.index + match[0].length + 60);
      let context = content.slice(start, end).replace(/\n/g, ' ');
      if (start > 0) context = '...' + context;
      if (end < content.length) context = context + '...';

      const finding = normalizeFinding({
        type: entry.finding_type || name,
        raw_value: value.slice(0, 1000),
        severity: entry.severity,
        detector_id: entry.detector_id || name,
        category: entry.category || entry.pack || 'leak',
        description: entry.description,
        risk_reason: entry.description,
        remediation: entry.remediation,
        references: entry.references || [],
        validation_status: entry.validation_status || 'lead',
        source,
        context: redactSnippet(context, value),
        timestamp: Date.now(),
        ...meta,
      });

      // AIza key classification: downgrade for Maps/Firebase context
      if ((name === 'gemini_api_key' || entry.finding_type === 'gemini_api_key') && value.startsWith('AIza')) {
        const contentLower = content.toLowerCase();
        const sourceLower = source.toLowerCase();
        const MAPS_MARKERS = [
          'maps.googleapis.com', 'googleapis.com/maps', 'google.maps',
          'firebaseconfig', 'firebaseapp', 'firebase.google.com', 'firebase',
          'google-analytics.com', 'googletagmanager.com',
          'gapi.client', 'accounts.google.com',
          'gtag(', 'ga(', 'googleanalyticsobject',
          'youtube.googleapis.com', 'maps.google.com',
          '@firebase/', 'firebase/performance', 'firebase/auth',
          'firebase/firestore', 'firebase/storage', 'firebase/messaging',
        ];
        if (MAPS_MARKERS.some(m => contentLower.includes(m) || sourceLower.includes(m))) {
          finding.type = 'google_client_api_key';
          finding.severity = 'medium';
          finding.risk_reason = 'Google Maps/Firebase client API key (referrer-restricted, expected in browser bundles).';
          finding.remediation = 'Verify the key has referrer restrictions set in Google Cloud Console. Client-side Google API keys are expected but should be locked to your domain.';
        }
      }

      findings.push(finding);

      // Cap at 50 findings per content block to prevent flooding
      if (findings.length >= 50) return findings;
    }
  }

  return findings;
}

/**
 * Analyze HTTP headers for secrets.
 * @param {Array<{name: string, value: string}>} headers
 * @param {string} source
 * @returns {Array<Object>}
 */
export function analyzeHeaders(headers, source = 'Headers', meta = {}) {
  const findings = [];
  if (!headers) return findings;

  for (const header of headers) {
    const headerStr = `${header.name}: ${header.value}`;
    findings.push(...analyzeContent(headerStr, `${source} (${header.name})`, meta));
  }

  return findings;
}

/**
 * Analyze a URL for secrets in query parameters and path.
 * @param {string} url
 * @returns {Array<Object>}
 */
export function analyzeUrl(url, meta = {}) {
  if (!url) return [];
  return analyzeContent(url, 'URL', { ...meta, url });
}
