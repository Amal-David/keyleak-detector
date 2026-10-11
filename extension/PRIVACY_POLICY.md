# Privacy Policy — KeyLeak Detector Chrome Extension

**Last updated:** October 9, 2026

## What KeyLeak Does

KeyLeak Detector is a security tool whose live extension analysis runs entirely in your browser. The optional Full Scan runs in a local Docker container and requests the target you explicitly select.

## Data Collection

**KeyLeak does not send data to KeyLeak-operated services or third-party analytics.**

- Captured browser content is analyzed in the service worker and is not saved as page content
- Redacted findings and per-origin pause settings are stored in Chrome local storage
- Raw detected values stay only in service-worker memory and disappear when that worker restarts
- Except for explicitly requested Full Scan traffic, analyzed data is not sent over the network
- No analytics, telemetry, or tracking of any kind
- No user accounts or registration required
- Redacted findings are stored in Chrome local storage per tab and cleared when the tab closes. Raw detected values are never persisted; reveal and test controls work only while those values remain in service-worker memory.

## What the Extension Accesses

- **Web requests:** Observes request and response headers and page scripts may inspect response bodies on pages you visit to scan for secrets. This data never leaves your browser.
- **Page content:** Reads DOM, inline scripts, and browser storage to detect exposed credentials. This data never leaves your browser.
- **`<all_urls>` permission:** Required to scan any website you visit. The extension cannot read this data unless you are actively browsing the site.

The popup's **PAUSE SITE** control pauses monitoring for the current page origin and stores that choice in Chrome local storage. While paused, the extension avoids reading page response bodies, scanning page content, or analyzing and storing that page's web request headers, including requests from frames inside that page. **RESUME SITE** restores monitoring for that origin. An origin includes its scheme, host, and port; pausing it covers all paths on that origin, while subdomains are separate origins.

## Optional Local Scanner

The "Run Full Scan" feature connects to `http://127.0.0.1:5002`. After one-time setup, the extension can send fixed lifecycle messages to the KeyLeak native helper so it can open Docker Desktop, start this repository's local scanner, and keep it alive during the scan. Native messages carry only lifecycle actions plus a random challenge and its local proof; they contain no page URL, site credential, finding, or captured browser content. The extension verifies that proof before sending the selected URL to the authenticated extension scan endpoint. A helper-started container is stopped after about five minutes without extension activity; a scanner the helper did not start is left alone.

The selected target URL is sent to the loopback scanner, which makes scan requests to that authorized target. Browser cookies and bearer tokens are not forwarded by this action.

When the extension's BaaS read probe runs, KeyLeak requests at most two rows. If records are returned, the finding stores only a bounded structural preview: field names, masked string prefixes and lengths, and type markers. Emails, phone numbers, identifier-like tokens, numbers, booleans, nested values, and excess fields are masked or truncated.

The popup offers an explicit `REVEAL RAW SAMPLE` control for those one or two rows. Raw rows remain only in tab-scoped service-worker memory and are returned locally to the popup after that click. They are never written to extension storage, copied reports, logs, analytics, or native messages, and disappear on navigation, clear, tab close, or service-worker restart. An empty HTTP 200 response is labeled as readable but empty and has no reveal control.

For Convex, the extension observes the browser's existing WebSocket session. It forwards only an opaque per-socket identifier, query IDs, public function paths, and an authenticated/anonymous flag from client messages—never authentication tokens or query arguments. It confirms exposure only when the same anonymous socket receives query data. It does not invoke Convex queries, mutations, actions, HTTP actions, or guessed function names.

## Contact

For questions about this privacy policy: amal@utopianlabs.co

GitHub: https://github.com/Amal-David/keyleak-detector
