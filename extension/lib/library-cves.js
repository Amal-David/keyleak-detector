/**
 * Known-vulnerable frontend JavaScript library detection (retire.js-style).
 *
 * Port of keyleak/js_library_cves.py. The MAIN-world injector reads the
 * versions of libraries a page actually loads (see scanLibraries in
 * injector.js); this module maps a (library, version) pair to publicly
 * documented CVEs and builds appsec findings.
 *
 * Detection is version-based, so findings are reported as `lead`: a vulnerable
 * version is present, but whether the specific sink is reachable depends on how
 * the app uses the library. The signal is still high-value — shipping a
 * decade-old jQuery or an unpatched Bootstrap is a real, common exposure.
 *
 * Keep this table in sync with keyleak/js_library_cves.py (VULN_TABLE). Library
 * and version come from the page at runtime; CVE IDs are public, so nothing
 * target-specific lives here.
 */

const NVD_URL = 'https://nvd.nist.gov/vuln/detail/';

// Severity rank for picking the worst across multiple matched rules.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Each library maps to a list of rules. A rule matches when the parsed version
// is >= `introduced` (inclusive, default [0,0,0]) and < `below` (exclusive).
// A single version may match several rules; findings aggregate them.
const VULN_TABLE = {
  jquery: [
    {
      below: [1, 9, 0],
      severity: 'high',
      cves: ['CVE-2012-6708'],
      summary: 'jQuery < 1.9 cannot reliably tell a CSS selector from HTML, so $() on attacker-controlled input executes scripts (DOM XSS).',
    },
    {
      below: [3, 0, 0],
      severity: 'high',
      cves: ['CVE-2015-9251'],
      summary: 'jQuery < 3.0 auto-executes cross-domain AJAX responses served as text/javascript, enabling XSS.',
    },
    {
      below: [3, 4, 0],
      severity: 'high',
      cves: ['CVE-2019-11358'],
      summary: 'jQuery < 3.4 jQuery.extend(true, ...) is vulnerable to Object.prototype pollution.',
    },
    {
      below: [3, 5, 0],
      severity: 'high',
      cves: ['CVE-2020-11022', 'CVE-2020-11023'],
      summary: 'jQuery < 3.5 htmlPrefilter regex can be bypassed, so .html()/.append() on untrusted HTML executes scripts (XSS).',
    },
  ],
  bootstrap: [
    {
      below: [3, 4, 1],
      severity: 'medium',
      cves: ['CVE-2018-14041', 'CVE-2019-8331'],
      summary: 'Bootstrap < 3.4.1 has XSS in data-target and tooltip/popover templates.',
    },
    {
      introduced: [4, 0, 0],
      below: [4, 1, 2],
      severity: 'medium',
      cves: ['CVE-2018-14041'],
      summary: 'Bootstrap 4 < 4.1.2 has XSS in the scrollspy data-target attribute.',
    },
    {
      introduced: [4, 0, 0],
      below: [4, 3, 1],
      severity: 'medium',
      cves: ['CVE-2019-8331'],
      summary: 'Bootstrap 4 < 4.3.1 has XSS in tooltip/popover data-template.',
    },
    {
      introduced: [4, 0, 0],
      below: [4, 6, 3],
      severity: 'medium',
      cves: ['CVE-2024-6531'],
      summary: 'Bootstrap 4 (4.0.0–4.6.2) has XSS in the carousel data-slide / data-slide-to attributes.',
    },
  ],
};

// Latest safe major line per library, for remediation guidance.
const SAFE_TARGET = { jquery: '3.7.1 or later', bootstrap: '5.3.x or later' };

/**
 * Parse a loose version string into a [major, minor, patch] tuple.
 * Tolerates a leading `v`, pre-release/build suffixes (`3.5.0-beta`), and
 * missing patch/minor (`2` -> [2, 0, 0]). Returns null when no numeric version
 * can be recovered, so callers simply skip the library.
 */
export function parseVersion(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const text = raw.trim().replace(/^[vV]+/, '');
  // Take the leading dotted-numeric run, ignoring any -beta/+build suffix.
  let head = '';
  for (const ch of text) {
    if ((ch >= '0' && ch <= '9') || ch === '.') head += ch;
    else break;
  }
  // Reject malformed versions (leading dot or empty components like ".5",
  // "3..5", "1.2.") rather than silently coercing them to a wrong number.
  if (!head || head[0] === '.') return null;
  const parts = head.split('.').slice(0, 3);
  const nums = [];
  for (const part of parts) {
    if (part === '') return null;
    const value = Number(part);
    if (!Number.isInteger(value)) return null;
    nums.push(value);
  }
  while (nums.length < 3) nums.push(0);
  return [nums[0], nums[1], nums[2]];
}

function compareVersions(left, right) {
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
  }
  return 0;
}

/**
 * Return the vulnerability rules that apply to name@version.
 * Empty array when the library is unknown or the version is safe/unparseable.
 */
export function matchLibraryCves(name, version) {
  const rules = VULN_TABLE[String(name || '').trim().toLowerCase()];
  if (!rules) return [];
  const parsed = parseVersion(version);
  if (parsed === null) return [];
  const matched = [];
  for (const rule of rules) {
    const introduced = rule.introduced || [0, 0, 0];
    if (compareVersions(introduced, parsed) <= 0 && compareVersions(parsed, rule.below) < 0) {
      matched.push(rule);
    }
  }
  return matched;
}

/**
 * Build one appsec finding per distinct vulnerable (library, version).
 * `libraries` is the raw payload from the injector's library scan: objects with
 * `name`, `version`, `source` ('global'|'script-url'), and optional `url`.
 * Returns raw finding objects ready for normalizeFinding/addFindings.
 */
export function buildLibraryFindings(libraries, pageUrl = '') {
  const findings = [];
  const seen = new Set();
  for (const lib of libraries || []) {
    const name = String((lib || {}).name || '').trim().toLowerCase();
    const version = (lib || {}).version;
    if (!name || !version) continue;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const matched = matchLibraryCves(name, version);
    if (matched.length === 0) continue;

    const cves = [];
    for (const rule of matched) {
      for (const cve of rule.cves) {
        if (!cves.includes(cve)) cves.push(cve);
      }
    }
    const severity = matched
      .map(rule => rule.severity)
      .reduce((worst, current) => (SEVERITY_RANK[current] > SEVERITY_RANK[worst] ? current : worst));
    const summary = matched.map(rule => rule.summary).join(' ');
    const source = String(lib.url || pageUrl || '');
    const target = SAFE_TARGET[name] || 'a current, supported release';
    const label = `${name} ${version}`;

    findings.push({
      type: 'vulnerable_js_library',
      severity,
      detector_id: 'appsec.vulnerable_js_library',
      category: 'appsec',
      source: source || `Loaded library: ${label}`,
      raw_value: label,
      redacted_value: `${label} — ${cves.join(', ')}`,
      url: pageUrl || source,
      risk_reason: `${label} is loaded and has known vulnerabilities (${cves.join(', ')}). ${summary}`,
      remediation: `Upgrade ${name} to ${target} and re-test. Pin the dependency and track advisories so vulnerable versions are not reintroduced.`,
      references: cves.map(cve => `${NVD_URL}${cve}`),
      validation_status: 'lead',
      capture_type: 'library',
    });
  }
  return findings;
}
