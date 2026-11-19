/**
 * Optional acquisition for the static browser app. Analysis itself needs no network.
 *
 * These are normal browser requests: CORS/TLS still apply. Literal-host checks
 * cannot prove where a DNS name resolves, inspect the connected IP, or pin DNS.
 * No proxy, cookies, redirect following, automatic crawling, or key validation.
 */

const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const HARD_MAX_BYTES = 10 * 1024 * 1024;
const COMMON_LABELS = Object.freeze([
  'www', 'api', 'app', 'admin', 'dev', 'staging', 'cdn', 'static',
  'assets', 'mail', 'auth', 'beta', 'test', 'portal', 'mobile', 'status',
]);
const DNS_ENDPOINT = 'https://dns.google/resolve';
const DNS_MAX_BYTES = 64 * 1024;
const PRIVATE_SUFFIXES = [
  'localhost', 'local', 'localdomain', 'internal', 'lan', 'home', 'corp',
  'arpa', 'test', 'invalid', 'onion', 'alt', 'example',
];

export class NetworkAcquisitionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'NetworkAcquisitionError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new NetworkAcquisitionError(code, message);
}

function boundedInteger(value, fallback, maximum, name) {
  const result = value === undefined ? fallback : value;
  if (!Number.isInteger(result) || result < 1 || result > maximum) {
    fail('INVALID_OPTIONS', `${name} must be an integer between 1 and ${maximum}.`);
  }
  return result;
}

function isPublicIpv4(host) {
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  // Azure's virtual platform address is public-looking but not a public target.
  if (host === '168.63.129.16') return false;
  return true;
}

function ipv6Words(host) {
  const value = host.replace(/^\[/, '').replace(/\]$/, '');
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right];
  if (words.some((word) => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
  return words.map((word) => Number.parseInt(word, 16));
}

function isPublicIpv6(host) {
  const words = ipv6Words(host);
  if (!words || words.length !== 8) return false;
  // Conservatively allow current global unicast only. This excludes mapped,
  // translated/NAT64, loopback, local, multicast, and unspecified addresses.
  if ((words[0] & 0xe000) !== 0x2000) return false;
  if (words[0] === 0x2001 && words[1] < 0x0200) return false; // protocol assignments
  if (words[0] === 0x2001 && words[1] === 0x0db8) return false; // documentation
  if (words[0] === 0x2002) return false; // 6to4 may encode a private IPv4 endpoint
  if (words[0] === 0x3fff && words[1] < 0x1000) return false; // documentation
  return true;
}

function isPublicLiteralOrName(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[')) return isPublicIpv6(host);
  if (/^[0-9.]+$/.test(host)) return isPublicIpv4(host);
  if (host === 'metadata.goog' || host === 'instance-data') return false;
  if (PRIVATE_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`))) return false;
  if (!host.includes('.') || host.length > 253) return false;
  return host.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

/** Returns a canonical URL object; this is syntax/literal checking, not DNS validation. */
export function normalizePublicHttpsUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 8192) {
    fail('INVALID_URL', 'Enter an HTTPS resource URL.');
  }
  const input = rawUrl.trim();
  if (!input || /[\u0000-\u0020\u007f\\]/.test(input)) {
    fail('INVALID_URL', 'The URL contains unsupported whitespace, controls, or backslashes.');
  }
  let url;
  try {
    url = new URL(input);
  } catch {
    fail('INVALID_URL', 'Enter a valid HTTPS resource URL.');
  }
  if (url.protocol !== 'https:') fail('HTTPS_REQUIRED', 'Only HTTPS resources are supported.');
  // Detect even empty userinfo, which URL.username/password alone would miss.
  const authority = input.match(/^https:\/\/([^/?#]*)/i)?.[1];
  if (!authority || authority.includes('@') || url.username || url.password) {
    fail('URL_CREDENTIALS', 'URLs containing credentials are not supported.');
  }
  if (!isPublicLiteralOrName(url.hostname)) {
    fail('BLOCKED_HOST', 'Local, private, metadata, and special-use hosts are not supported.');
  }
  url.hash = '';
  return url;
}

function isTextContentType(type) {
  return type.startsWith('text/') || [
    'application/javascript', 'application/x-javascript', 'application/ecmascript',
    'application/json', 'application/xml', 'application/yaml', 'application/x-yaml',
    'application/graphql', 'application/sql', 'application/x-www-form-urlencoded',
  ].includes(type) || /^application\/[a-z0-9!#$&^_.+-]+\+(?:json|xml)$/.test(type);
}

function aborted() {
  return new NetworkAcquisitionError('ABORTED', 'The network operation was cancelled; no complete scan was produced.');
}

function abortable(promise, signal) {
  if (signal.aborted) {
    Promise.resolve(promise).catch(() => {});
    return Promise.reject(aborted());
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(aborted());
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => {
      signal.removeEventListener('abort', onAbort);
    });
  });
}

/**
 * Explicitly acquire one readable text resource for scanInputs(). The request
 * may contain a user-entered query; returned provenance omits query/fragment.
 */
export async function fetchPublicResource(rawUrl, options = {}) {
  const url = normalizePublicHttpsUrl(rawUrl);
  const maxBytes = boundedInteger(options.maxBytes, DEFAULT_MAX_BYTES, HARD_MAX_BYTES, 'maxBytes');
  const timeoutMs = boundedInteger(options.timeoutMs, 15000, 60000, 'timeoutMs');
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') fail('UNSUPPORTED_BROWSER', 'This browser does not support resource fetching.');
  if (options.signal?.aborted) throw aborted();
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  let reader;
  let responseBody;
  let completed = false;
  try {
    const response = await abortable(fetchImpl(url.href, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      cache: 'no-store',
      headers: { Accept: 'text/*, application/javascript, application/json, application/*+json, application/xml;q=0.9' },
      signal: controller.signal,
    }), controller.signal);
    responseBody = response?.body;
    if (!response || response.type === 'opaque' || response.type === 'opaqueredirect' || response.type === 'error') {
      fail('UNREADABLE_RESPONSE', 'The browser returned an unreadable response; this resource has not been scanned.');
    }
    if (response.redirected) fail('REDIRECT_BLOCKED', 'Redirects are not followed. Enter the final resource URL explicitly.');
    if (!response.ok) fail('HTTP_ERROR', `The server returned HTTP ${Number(response.status) || 0}; this resource has not been scanned.`);
    const type = (response.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
    if (!isTextContentType(type)) {
      fail('UNSUPPORTED_CONTENT_TYPE', 'The server did not return a supported text content type. Download it and use local file scanning if appropriate.');
    }
    const declaredLength = response.headers.get('content-length');
    if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxBytes) {
      fail('RESOURCE_TOO_LARGE', `The resource exceeds the ${maxBytes}-byte acquisition limit.`);
    }
    const decoder = new TextDecoder();
    let size = 0;
    const pieces = [];
    if (response.body) {
      if (typeof response.body.getReader !== 'function') {
        fail('UNSUPPORTED_BROWSER', 'Bounded streaming responses are unavailable in this browser.');
      }
      reader = response.body.getReader();
      while (true) {
        const { done, value } = await abortable(reader.read(), controller.signal);
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) fail('RESOURCE_TOO_LARGE', `The resource exceeds the ${maxBytes}-byte acquisition limit.`);
        pieces.push(decoder.decode(value, { stream: true }));
      }
    }
    pieces.push(decoder.decode());
    completed = true;
    const sourceUrl = `${url.origin}${url.pathname}`;
    return {
      name: `${url.hostname}${url.pathname}`,
      content: pieces.join(''),
      type,
      sourceUrl,
    };
  } catch (error) {
    if (timedOut) fail('TIMEOUT', 'The resource request timed out; this resource has not been scanned.');
    if (options.signal?.aborted) throw aborted();
    if (error instanceof NetworkAcquisitionError) throw error;
    // Browser Fetch intentionally does not expose a reliable CORS vs TLS vs
    // redirect vs other network-error classification. Never call this "clean".
    fail('NETWORK_OR_CORS', 'The browser could not read this resource. CORS, TLS, a blocked redirect, or network policy may prevent access; this resource has not been scanned.');
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', onAbort);
    if (!completed) {
      controller.abort();
      try {
        const cancellation = reader ? reader.cancel() : responseBody?.cancel();
        Promise.resolve(cancellation).catch(() => {});
      } catch { /* abort already stops native Fetch even if stream cancellation fails */ }
    }
    try { reader?.releaseLock(); } catch { /* a cancelled read may still be settling */ }
  }
}

function normalizeDiscoveryDomain(rawDomain) {
  if (typeof rawDomain !== 'string' || /[:/@?#\[\]\\]/.test(rawDomain)) {
    fail('INVALID_DOMAIN', 'Enter a domain name without a scheme, port, path, or credentials.');
  }
  const domain = rawDomain.trim().replace(/\.$/, '');
  const url = normalizePublicHttpsUrl(`https://${domain}/`);
  if (/^[0-9.]+$/.test(url.hostname) || url.hostname.length > 237) {
    fail('INVALID_DOMAIN', 'Enter a public domain name suitable for subdomain discovery.');
  }
  return url.hostname;
}

function randomControlLabel() {
  const bytes = new Uint8Array(6);
  if (!globalThis.crypto?.getRandomValues) fail('UNSUPPORTED_BROWSER', 'Secure randomness is required for DNS wildcard checks.');
  globalThis.crypto.getRandomValues(bytes);
  return `kl-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function validDnsAddress(data, recordType) {
  if (typeof data !== 'string') return null;
  if (recordType === 1) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(data)) return null;
    const parts = data.split('.').map(Number);
    return parts.every((part) => part <= 255) ? parts.join('.') : null;
  }
  if (recordType === 28) {
    try {
      const url = new URL(`https://[${data}]/`);
      return url.hostname.slice(1, -1);
    } catch { return null; }
  }
  return null;
}

function dnsName(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.toLowerCase().replace(/\.$/, '');
  if (!normalized || normalized.length > 253 || !normalized.split('.').every((label) => /^[a-z0-9_-]{1,63}$/.test(label))) return null;
  return normalized;
}

function parseDnsResult(content, hostname) {
  let data;
  try { data = JSON.parse(content); } catch {
    fail('DNS_INVALID_RESPONSE', 'The DNS resolver returned invalid JSON.');
  }
  if (!data || Array.isArray(data) || !Number.isInteger(data.Status) || (data.Answer !== undefined && !Array.isArray(data.Answer))) {
    fail('DNS_INVALID_RESPONSE', 'The DNS resolver returned an invalid response.');
  }
  if (data.TC === true) fail('DNS_TRUNCATED', 'The DNS answer was truncated and cannot be treated as complete.');
  if (data.Status === 3) return { exists: false, addresses: [], recordTypes: [] };
  if (data.Status !== 0) fail('DNS_ERROR', `The DNS resolver reported DNS status ${data.Status}.`);
  const answers = data.Answer ?? [];
  if (answers.length > 64) fail('DNS_INVALID_RESPONSE', 'The DNS answer exceeds the bounded record limit.');
  if (answers.some((record) => !record || !Number.isInteger(record.type) || !dnsName(record.name))) {
    fail('DNS_INVALID_RESPONSE', 'The DNS resolver returned malformed answer records.');
  }
  // Only accept records for the requested name or its explicit CNAME chain.
  // CNAMEs outside the target suffix are evidence, never additional fetch jobs.
  const relatedNames = new Set([hostname]);
  for (let step = 0; step < answers.length; step += 1) {
    let changed = false;
    for (const record of answers) {
      if (record.type !== 5 || !relatedNames.has(dnsName(record.name))) continue;
      const target = dnsName(record.data);
      if (!target) fail('DNS_INVALID_RESPONSE', 'The DNS resolver returned a malformed CNAME target.');
      if (!relatedNames.has(target)) { relatedNames.add(target); changed = true; }
    }
    if (!changed) break;
  }
  const addresses = new Set();
  const recordTypes = new Set();
  for (const record of answers) {
    if (!relatedNames.has(dnsName(record.name))) continue;
    const address = validDnsAddress(record.data, record.type);
    if (address) {
      addresses.add(address);
      recordTypes.add(record.type === 1 ? 'A' : 'AAAA');
    } else if (record.type === 5) {
      recordTypes.add('CNAME');
    } else if (record.type === 1 || record.type === 28) {
      fail('DNS_INVALID_RESPONSE', 'The DNS resolver returned a malformed IP address.');
    }
  }
  return { exists: recordTypes.size > 0, addresses: [...addresses], recordTypes: [...recordTypes] };
}

async function mapLimited(values, concurrency, callback, signal) {
  const result = Array(values.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (next < values.length) {
      if (signal.aborted) throw aborted();
      const index = next++;
      result[index] = await callback(values[index]);
    }
  });
  await Promise.all(workers);
  return result;
}

/**
 * Explicit, limited common-label DNS discovery. This sends candidate names and
 * the client's IP to Google Public DNS. It does not enumerate a DNS zone, fetch
 * discovered websites, contact private IPs, or validate any discovered secrets.
 */
export async function discoverSubdomains(rawDomain, options = {}) {
  const domain = normalizeDiscoveryDomain(rawDomain);
  if (options.resolver !== undefined && options.resolver !== 'google') {
    fail('UNSUPPORTED_RESOLVER', 'This preview supports only the fixed Google Public DNS resolver.');
  }
  const maxCandidates = boundedInteger(options.maxCandidates, 8, COMMON_LABELS.length, 'maxCandidates');
  const concurrency = boundedInteger(options.concurrency, 2, 4, 'concurrency');
  const timeoutMs = boundedInteger(options.timeoutMs, 8000, 15000, 'timeoutMs');
  const totalTimeoutMs = boundedInteger(options.totalTimeoutMs, 45000, 120000, 'totalTimeoutMs');
  if (options.signal?.aborted) throw aborted();
  const controls = [randomControlLabel(), randomControlLabel()].map((label) => `${label}.${domain}`);
  const hosts = COMMON_LABELS.slice(0, maxCandidates).map((label) => `${label}.${domain}`);
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; controller.abort(); }, totalTimeoutMs);
  const errors = [];
  let requests = 0;
  const query = async ({ hostname, recordType }) => {
    const url = new URL(DNS_ENDPOINT);
    url.searchParams.set('name', hostname);
    url.searchParams.set('type', recordType);
    // Avoid forwarding the client's subnet to authoritative DNS via ECS. The
    // selected resolver still sees the client's address and full query names.
    url.searchParams.set('edns_client_subnet', '0.0.0.0/0');
    requests += 1;
    try {
      const resource = await fetchPublicResource(url.href, {
        signal: controller.signal,
        maxBytes: DNS_MAX_BYTES,
        timeoutMs,
        fetchImpl: options.fetchImpl,
      });
      return { hostname, ...parseDnsResult(resource.content, hostname) };
    } catch (error) {
      if (controller.signal.aborted) throw aborted();
      errors.push({
        hostname,
        recordType,
        code: error instanceof NetworkAcquisitionError ? error.code : 'DNS_ERROR',
        message: error instanceof NetworkAcquisitionError ? error.message : 'The DNS lookup failed.',
      });
      return { hostname, exists: false, addresses: [], recordTypes: [], failed: true };
    }
  };
  const tasks = (names) => names.flatMap((hostname) => ['A', 'AAAA'].map((recordType) => ({ hostname, recordType })));
  try {
    const controlResults = await mapLimited(tasks(controls), concurrency, query, controller.signal);
    const wildcardDetected = controlResults.some((result) => result.exists);
    const wildcardStatus = wildcardDetected ? 'detected' : controlResults.some((result) => result.failed) ? 'inconclusive' : 'not-detected';
    const results = await mapLimited(tasks(hosts), concurrency, query, controller.signal);
    const subdomains = hosts.flatMap((hostname) => {
      const answers = results.filter((result) => result.hostname === hostname);
      if (!answers.some((answer) => answer.exists)) return [];
      return [{
        hostname,
        addresses: [...new Set(answers.flatMap((answer) => answer.addresses))],
        recordTypes: [...new Set(answers.flatMap((answer) => answer.recordTypes))],
        source: 'Google Public DNS over HTTPS',
        wildcardSuspected: wildcardDetected,
      }];
    });
    return {
      domain,
      resolver: 'google',
      subdomains,
      errors,
      wildcardDetected,
      wildcardStatus,
      complete: errors.length === 0,
      stats: { requests, candidatesChecked: hosts.length, wildcardControlNames: controls.length },
      notice: 'Limited common-label DNS lookup only. Google receives the queried names and your IP address. No discovered website was fetched. Wildcard DNS can make unconfigured names resolve; absence of an answer is not proof that a subdomain does not exist.',
    };
  } catch (error) {
    if (timedOut) fail('DISCOVERY_TIMEOUT', 'DNS discovery reached its overall time limit and is incomplete.');
    if (options.signal?.aborted) throw aborted();
    throw error;
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', onAbort);
    controller.abort();
  }
}
