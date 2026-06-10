/**
 * SSRF hardening for the service worker's remote-resource fetches (audit W11/S2).
 *
 * The service worker fetches URLs discovered inside page content (scripts,
 * source maps). A hostile page must not be able to steer those fetches at the
 * user's localhost, LAN, or cloud-metadata endpoints. We block obvious internal
 * / non-routable literal hosts UNLESS the target is the same host the user is
 * already on (so scanning a localhost dev app still works).
 *
 * Limitation: only literal IPs and localhost are recognized. A DNS name that
 * resolves to an internal address is not caught here — browser `fetch` cannot
 * pre-resolve, and `redirect: 'follow'` can hop to an internal host after the
 * fact. This raises the bar against the direct attack without claiming to be a
 * complete SSRF defense.
 */

function isBlockedIpv4(a, b, c, d) {
  if ([a, b, c, d].some((o) => o > 255 || o < 0 || Number.isNaN(o))) return true; // malformed → block
  if (a === 127) return true;                          // loopback
  if (a === 10) return true;                           // RFC1918
  if (a === 0) return true;                            // unspecified / "this network"
  if (a === 169 && b === 254) return true;             // link-local incl. cloud metadata
  if (a === 192 && b === 168) return true;             // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true;    // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true;   // CGNAT (RFC6598)
  return false;
}

export function isBlockedScanHost(hostname) {
  if (!hostname) return true;
  const host = String(hostname).toLowerCase().replace(/^\[/, '').replace(/\]$/, '');

  if (host === 'localhost' || host.endsWith('.localhost')) return true;

  // IPv6 literals only: loopback, unspecified, link-local (fe80::/10),
  // unique-local (fc00::/7). Gate on a colon so public domains like
  // 'fc-barcelona.com' or 'fd-foo.io' are NOT blocked.
  if (host.includes(':')) {
    if (host === '::1' || host === '::') return true;
    if (host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) return true;
  }

  // IPv4-mapped / -translated IPv6 and NAT64. The WHATWG URL parser normalizes
  // the dotted form to hex (::ffff:a9fe:a9fe), so handle both — otherwise
  // http://[::ffff:169.254.169.254]/ would reach cloud metadata (gate MF-1).
  // Also covers ::ffff:0:x.x.x.x (translated) and 64:ff9b::x.x.x.x (NAT64) by
  // extracting any trailing 32-bit IPv4 (dotted or two hex groups).
  if (host.includes(':') && (host.includes('ffff:') || host.startsWith('64:ff9b'))) {
    const dotted = host.match(/:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (dotted) {
      if (isBlockedIpv4(Number(dotted[1]), Number(dotted[2]), Number(dotted[3]), Number(dotted[4]))) return true;
    }
    const hex = host.match(/:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      if (isBlockedIpv4((hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff)) return true;
    }
  }

  // IPv4 literal
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    return isBlockedIpv4(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]));
  }
  return false;
}

export function canScanUrl(url, pageUrl) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (_error) {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

  if (isBlockedScanHost(parsed.hostname)) {
    // Permit an internal target only when it shares the SAME ORIGIN (protocol +
    // host + port) the user already navigated to — e.g. their own localhost dev
    // server. A hostname-only check would let a page on 127.0.0.1:8080 unlock
    // fetches to 127.0.0.1:6379 (Redis), :22, etc. (gate MF-3).
    let pageOrigin = '';
    try {
      pageOrigin = new URL(pageUrl).origin;
    } catch (_error) {
      pageOrigin = '';
    }
    if (!pageOrigin || parsed.origin !== pageOrigin) return false;
  }
  return true;
}
