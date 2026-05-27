# Privacy Policy — KeyLeak Detector Chrome Extension

**Last updated:** May 27, 2026

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

## Optional Local Server

The "Run Full Scan" feature connects to `http://127.0.0.1:5002` — a local Python server you run on your own machine. No data leaves your local network.

## Contact

For questions about this privacy policy: amal@utopianlabs.co

GitHub: https://github.com/Amal-David/keyleak-detector
