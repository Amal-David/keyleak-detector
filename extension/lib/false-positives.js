/**
 * False positive filtering for KeyLeak Detector.
 * Ported from Python app.py is_false_positive().
 */

const FALSE_POSITIVE_VALUES = new Set([
  'api_key', 'your_api_key', 'example.com', 'test', 'password',
  'secret_key', 'change_this', 'your_password', 'your_secret_key',
  '00000000-0000-0000-0000-000000000000', '1234567890', '0123456789',
  'client_id', 'client_secret', 'access_token', 'refresh_token',
  'bearer', 'basic', 'token', 'key', 'secret', 'undefined', 'null',
  'true', 'false', 'yes', 'no', 'example', 'demo', 'dummy',
  'development', 'staging', 'production', 'localhost', '127.0.0.1',
]);

const CSS_PATTERNS = [
  /^\.[\w-]+$/,
  /^\[_ng[\w-]+\]$/,
  /^[\w-]+\[_ng[\w-]+\]$/,
  /^\{[\w\s,]+\}$/,
  /^[\w-]+:[\w-]+$/,
  /^@[\w-]/,
  /^\d+px$/,
  /^\d+rem$/,
  /^#[0-9a-fA-F]{3,6}$/,
  /^rgb\(/,
  /^rgba\(/,
];

const CSS_KEYWORDS = [
  'cursor:', 'background:', 'margin:', 'padding:', 'font-',
  'color:', 'width:', 'height:',
];

const JS_BUILTINS = [
  'encodeuricomponent', 'decodeuricomponent', 'encodeuri', 'decodeuri',
  'btoa', 'atob', 'settimeout', 'setinterval', 'clearinterval',
  'getelementbyid', 'queryselector', 'queryselectorall', 'addeventlistener',
  'json.parse', 'json.stringify', 'object.keys', 'object.values',
  'array.from', 'array.isarray', 'math.random', 'math.floor',
  'date.now', 'localstorage', 'sessionstorage', 'fetch',
  'xmlhttprequest', 'promise', 'console.log', 'console.error',
  'document.cookie', 'window.location',
];

const PLACEHOLDER_PATTERNS = [
  /\b(?:replace|enter|your|add|insert|set|use)[_\- ]*(?:your|the|this|a)?[_\- ]*(?:api[_-]?key|key|secret|token|password|pwd|credential|id)\b/i,
  /\b(?:YOUR[_-]?)?(API[_-]?KEY|SECRET[_-]?KEY|TOKEN|PASSWORD|PWD|CREDENTIALS?|ID)\b/,
  /\b(?:test|dev|staging|prod|production)[_-](?:key|secret|token|password)\b/i,
  /\b(?:example|sample|dummy|placeholder)[_-](?:key|secret|token|password)\b/i,
];

/**
 * Check if a matched value is likely a false positive.
 * @param {string} value - The matched secret value
 * @returns {boolean} true if false positive
 */
export function isFalsePositive(value) {
  if (!value || typeof value !== 'string') return true;
  value = value.trim();
  if (value.length < 10 || value.length > 1000) return true;

  const lower = value.toLowerCase();

  // Known false positive values — only match if the value IS the false positive
  // (not just contains it as a substring, which would catch real keys like AKIA...1234567890...)
  if (FALSE_POSITIVE_VALUES.has(lower)) return true;

  // Too few unique characters
  if (/^\d+$/.test(value) || /^[a-zA-Z]+$/.test(value)) {
    if (new Set(value).size < 5) return true;
  }

  // CSS patterns
  for (const re of CSS_PATTERNS) {
    if (re.test(value)) return true;
  }
  for (const kw of CSS_KEYWORDS) {
    if (lower.includes(kw)) return true;
  }

  // JS builtins
  const normalized = lower.replace(/[_-]/g, '');
  for (const builtin of JS_BUILTINS) {
    if (normalized.includes(builtin)) return true;
  }

  // Placeholder patterns
  for (const re of PLACEHOLDER_PATTERNS) {
    if (re.test(value)) return true;
  }

  // Repeating digits
  if (/^(\d)\1{3,}$/.test(value)) return true;

  // Hex colors
  if (/^#[0-9a-fA-F]{3,8}$/.test(value)) return true;

  // IP addresses in reserved ranges
  const ipMatch = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipMatch) {
    const first = parseInt(ipMatch[1], 10);
    if ([0, 10, 127, 169, 172, 192, 224, 240, 255].includes(first)) return true;
  }

  // Base64-encoded short values (common in minified JS, not secrets)
  // Exclude values with path separators (like /users/123456)
  if (/^[A-Za-z0-9+/]{10,}={0,2}$/.test(value) && value.length < 20 && !value.includes('/')) return true;

  // Version strings and semver
  if (/^\d+\.\d+\.\d+/.test(value)) return true;

  // UUIDs (not secrets — identifiers)
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true;

  // Package names / npm scoped packages
  if (/^@[a-z0-9-]+\/[a-z0-9-]+$/.test(lower)) return true;

  // Common minified JS operator sequences matched by broad detectors
  if (/^(?:delete|select|update|insert)\s+[a-z]\.[_$a-z]/i.test(value) && value.length < 40) return true;

  // JWT-shaped strings that are actually just base64 config blobs (too short to be real JWTs)
  if (/^eyJ/.test(value) && value.length < 50) return true;

  return false;
}

/**
 * Check if a finding source is a browser-internal or extension-internal URL.
 * @param {string} source
 * @returns {boolean}
 */
export function isBrowserInternal(source) {
  if (!source) return false;
  const s = String(source).toLowerCase();
  return s.startsWith('chrome-extension://') ||
         s.startsWith('chrome://') ||
         s.startsWith('moz-extension://') ||
         s.startsWith('about:') ||
         s.startsWith('edge://') ||
         s.startsWith('brave://') ||
         s.includes('devtools://');
}

const VENDOR_SCRIPT_DOMAINS = [
  'google-analytics.com',
  'googletagmanager.com',
  'googleapis.com',
  'gstatic.com',
  'google.com/maps',
  'maps.google.com',
  'posthog.com',
  'cdn.segment.com',
  'cdn.mxpnl.com',
  'js.intercomcdn.com',
  'widget.intercom.io',
  'js.stripe.com',
  'cdn.amplitude.com',
  'cdn.heapanalytics.com',
  'static.hotjar.com',
  'plausible.io',
  'cdn.lr-intake.com',
  'cdn.rudderlabs.com',
  'cdn.cookielaw.org',
  'js.hs-scripts.com',
  'js.hs-analytics.net',
  'connect.facebook.net',
  'snap.licdn.com',
  'static.ads-twitter.com',
  'bat.bing.com',
  'cdn.datadog-static.com',
  'browser-intake-datadoghq.com',
  'cdn.pendo.io',
  'js.sentry-cdn.com',
  'cdn.logrocket.io',
  'cdn.mouseflow.com',
  'static.cloudflareinsights.com',
  'challenges.cloudflare.com',
  'cdn.optimizely.com',
  'cdn.launchdarkly.com',
  'js.driftt.com',
  'widget.freshdesk.com',
  'js.chargebee.com',
  'js.recurly.com',
  'js.braintreegateway.com',
  'checkout.razorpay.com',
  'cdn.paddle.com',
  // Public CDNs serving open-source libraries
  'cdn.jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'esm.sh',
  'esm.run',
  'cdn.skypack.dev',
  'ga.jspm.io',
  'jspm.dev',
  'deno.land',
  // Framework-specific CDNs
  'ajax.googleapis.com/ajax/libs',
  'code.jquery.com',
  'cdn.tailwindcss.com',
  'cdn.shopify.com',
  // Error tracking / monitoring
  'js.bugsnag.com',
  'cdn.rollbar.com',
  'browser.sentry-cdn.com',
  // Chat / support widgets
  'cdn.zendesk.com',
  'embed.tawk.to',
  'static.zdassets.com',
  'widget.crisp.chat',
  // HubSpot
  'js.hscollectedforms.net',
  'js.hsforms.net',
  'js.hubspot.com',
  'js.hs-banner.com',
  'js.usemessages.com',
  // Widget / embed CDNs
  'elfsightcdn.com',
  'static.elfsight.com',
  'cdn.embedly.com',
  'platform.twitter.com',
  'platform.instagram.com',
  'connect.facebook.net',
  'apis.google.com',
  'www.youtube.com/iframe_api',
  'player.vimeo.com',
  'fast.wistia.com',
  // CMS / site builder
  'cdn.shopify.com/s',
  'assets.squarespace.com',
  'static.parastorage.com',
  'static.wixstatic.com',
  'cdn.webflow.com',
  // Consent / cookie managers
  'cdn.cookiebot.com',
  'consent.cookiebot.com',
  'cdn.iubenda.com',
  'cdn.onetrust.com',
];

/**
 * Check if a finding source is a known third-party vendor script.
 * Keys found in vendor CDN scripts are the vendor's own internal keys
 * (e.g., Google's AIza key in analytics.js), not user-leaked secrets.
 * @param {string} source - The source URL or description
 * @returns {boolean} true if from a vendor script
 */
// Infrastructure response headers whose values look like secrets but aren't.
// CloudFront x-amz-cf-id often starts with HF_ (matches HuggingFace regex),
// cf-ray contains hex tokens, x-request-id contains UUIDs, etc.
const INFRA_HEADER_PATTERNS = [
  'x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-request-id', 'x-amz-id-2',
  'x-cache', 'x-served-by', 'x-timer', 'x-request-id', 'x-trace-id',
  'x-cloud-trace-context', 'x-b3-traceid', 'x-b3-spanid',
  'cf-ray', 'cf-cache-status', 'cf-request-id',
  'x-vercel-id', 'x-vercel-cache',
  'x-fly-request-id', 'x-render-origin-server',
  'x-powered-by', 'server', 'via', 'x-cdn',
  'nel', 'report-to', 'reporting-endpoints',
  'x-nf-request-id',
  'etag', 'x-correlation-id',
];

/**
 * Check if a finding source is an infrastructure response header.
 * Values from these headers (trace IDs, cache keys, CDN identifiers)
 * often match secret patterns but are not credentials.
 * @param {string} source - The source label (e.g., "Response Header (x-amz-cf-id)")
 * @returns {boolean}
 */
export function isInfraHeader(source) {
  if (!source || typeof source !== 'string') return false;
  const lower = source.toLowerCase();
  if (!lower.includes('header')) return false;
  return INFRA_HEADER_PATTERNS.some(h => lower.includes(h));
}

export function isVendorScript(source) {
  if (!source || typeof source !== 'string') return false;
  const lower = source.toLowerCase();
  return VENDOR_SCRIPT_DOMAINS.some(domain => lower.includes(domain));
}

// Cloud storage signed/pre-signed URL patterns.
// These embed credentials or tokens in the URL for time-limited, scoped
// access to a single object.  They are designed to be shared publicly
// (in meta tags, image src, API responses) and are NOT leaked secrets.
const CLOUD_STORAGE_SIGNED_URL_MARKERS = [
  // AWS S3 / CloudFront pre-signed URLs
  'x-amz-credential',
  'x-amz-signature',
  'x-amz-date',
  'x-amz-expires',
  'x-amz-security-token',
  'x-amz-algorithm',
  'amazonaws.com',
  '.s3.',
  's3-',
  'cloudfront.net',

  // Google Cloud Storage signed URLs
  'x-goog-credential',
  'x-goog-signature',
  'x-goog-date',
  'x-goog-expires',
  'x-goog-algorithm',
  'storage.googleapis.com',
  'storage.cloud.google.com',

  // Azure Blob Storage SAS tokens
  'blob.core.windows.net',
  'blob.storage.azure.net',

  // Cloudflare R2 (uses S3-compatible signed URLs)
  'r2.dev',
  'r2.cloudflarestorage.com',

  // DigitalOcean Spaces (S3-compatible)
  'digitaloceanspaces.com',

  // Backblaze B2
  'backblazeb2.com',
  'f000.backblazeb2.com',

  // Wasabi
  'wasabisys.com',

  // Supabase Storage
  'supabase.co/storage',

  // Firebase Storage
  'firebasestorage.googleapis.com',

  // Vercel Blob
  'vercel-storage.com',
  'blob.vercel-storage.com',

  // Uploadthing / other upload services
  'uploadthing.com',
  'utfs.io',
];

// Patterns in the source label that indicate cloud storage / CDN context
const CLOUD_STORAGE_SOURCE_PATTERNS = [
  'meta tag',
  'presigned',
  'signed url',
  'og:image',
  'twitter:image',
];

/**
 * Check if a finding is from a cloud storage signed/pre-signed URL.
 * Covers AWS S3, GCS, Azure Blob, Cloudflare R2, DigitalOcean Spaces,
 * Backblaze B2, Wasabi, Supabase Storage, Firebase Storage, and Vercel Blob.
 * @param {string} value - The matched secret value
 * @param {string} source - Where it was found (source label)
 * @param {string} content - The full text being scanned
 * @returns {boolean} true if from a cloud storage signed URL context
 */
export function isCloudStorageSignedUrl(value, source, content) {
  const s = String(source || '').toLowerCase();
  const c = String(content || '').toLowerCase();

  // Check source label
  for (const pattern of CLOUD_STORAGE_SOURCE_PATTERNS) {
    if (s.includes(pattern)) return true;
  }

  // Check content and source for any cloud storage marker
  for (const marker of CLOUD_STORAGE_SIGNED_URL_MARKERS) {
    if (c.includes(marker) || s.includes(marker)) return true;
  }

  return false;
}

// Azure SAS token patterns — sv=, sig=, se=, sp= in query strings
const AZURE_SAS_RE = /[?&](?:sv|sig|se|sp|spr|srt)=/i;

/**
 * Check if a finding is from an Azure SAS token URL.
 * @param {string} content - The full text being scanned
 * @returns {boolean}
 */
export function isAzureSasToken(content) {
  return AZURE_SAS_RE.test(String(content || ''));
}
