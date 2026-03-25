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

  return false;
}
