# Privacy Policy — KeyLeak Detector Chrome Extension

**Last updated:** September 15, 2026

## What KeyLeak Does

KeyLeak Detector is a security tool that runs entirely in your browser. It analyzes web traffic to detect exposed API keys, BaaS misconfigurations, and secrets in JavaScript bundles.

## Data Collection

**KeyLeak does NOT collect, transmit, or store any user data.**

- All analysis happens locally in your browser
- No data is sent to any external server
- No analytics, telemetry, or tracking of any kind
- No user accounts or registration required
- Findings are stored only in Chrome's local storage (per-tab, cleared when tab closes)

## What the Extension Accesses

- **Web requests:** Intercepts HTTP requests/responses on pages you visit to scan for secrets. This data never leaves your browser.
- **Page content:** Reads DOM, inline scripts, and browser storage to detect exposed credentials. This data never leaves your browser.
- **`<all_urls>` permission:** Required to scan any website you visit. The extension cannot read this data unless you are actively browsing the site.

## Optional Local Scanner

The "Run Full Scan" feature connects to `http://127.0.0.1:5002`. After one-time setup, the extension can send fixed lifecycle messages to the KeyLeak native helper so it can open Docker Desktop, start this repository's local scanner, and keep it alive during the scan. Native messages carry only lifecycle actions plus a random challenge and its local proof; they contain no page URL, site credential, finding, or captured browser content. The extension verifies that proof before sending the selected URL to the authenticated extension scan endpoint. A helper-started container is stopped after about five minutes without extension activity; a scanner the helper did not start is left alone.

The selected target URL is sent to the loopback scanner, which makes scan requests to that authorized target. Browser cookies and bearer tokens are not forwarded by this action.

When the extension's BaaS read probe runs, KeyLeak requests at most two rows. If records are returned, the finding stores only a bounded structural preview: field names, masked string prefixes and lengths, and type markers. Emails, phone numbers, identifier-like tokens, numbers, booleans, nested values, and excess fields are masked or truncated.

The popup offers an explicit `REVEAL RAW SAMPLE` control for those one or two rows. Raw rows remain only in tab-scoped service-worker memory and are returned locally to the popup after that click. They are never written to extension storage, copied reports, logs, analytics, or native messages, and disappear on navigation, clear, tab close, or service-worker restart. An empty HTTP 200 response is labeled as readable but empty and has no reveal control.

For Convex, the extension observes the browser's existing WebSocket session. It forwards only an opaque per-socket identifier, query IDs, public function paths, and an authenticated/anonymous flag from client messages—never authentication tokens or query arguments. It confirms exposure only when the same anonymous socket receives query data. It does not invoke Convex queries, mutations, actions, HTTP actions, or guessed function names.

## Contact

For questions about this privacy policy: amal@utopianlabs.co

GitHub: https://github.com/Amal-David/keyleak-detector
