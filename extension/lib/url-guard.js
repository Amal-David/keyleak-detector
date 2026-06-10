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

export function isBlockedScanHost(hostname) {
  if (!hostname) return true;
  const host = String(hostname).toLowerCase().replace(/^\[/, '').replace(/\]$/, '');

  if (host === 'localhost' || host.endsWith('.localhost')) return true;

  // IPv6: loopback, unspecified, link-local (fe80::/10), unique-local (fc00::/7)
  if (host === '::1' || host === '::') return true;
  if (host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) return true;

  // IPv4 literal
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a > 255 || b > 255 || Number(m[3]) > 255 || Number(m[4]) > 255) return true; // malformed → block
    if (a === 127) return true;                          // loopback
    if (a === 10) return true;                           // RFC1918
    if (a === 0) return true;                            // unspecified / "this network"
    if (a === 169 && b === 254) return true;             // link-local incl. cloud metadata
    if (a === 192 && b === 168) return true;             // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true;    // RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true;   // CGNAT (RFC6598)
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
    // Permit an internal target only when it matches the host the user already
    // navigated to (e.g. their own localhost dev server). Otherwise refuse.
    let pageHost = '';
    try {
      pageHost = new URL(pageUrl).hostname.toLowerCase();
    } catch (_error) {
      pageHost = '';
    }
    if (!pageHost || parsed.hostname.toLowerCase() !== pageHost) return false;
  }
  return true;
}
