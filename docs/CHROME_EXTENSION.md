# Chrome extension

The extension observes request and response metadata, page content, and
fetch/XHR responses locally. It redacts stored and copied findings, keeps raw
finding values in service-worker memory, and lets you pause collection for an
origin. `nativeMessaging` is used for explicit full scans through the installed
local helper; it sends fixed lifecycle actions, a startup challenge, and local
proof, not page URLs or scan data.

- [Install the published Chrome Web Store extension](https://chromewebstore.google.com/detail/keyleak-detector/ildodbfchnbmndkcijllpmihcbfchgdl) (listing version **1.2.0**).
- [Download extension v1.3.0](https://github.com/Amal-David/keyleak-detector/releases/download/v0.7.0/keyleak-detector-extension-v1.3.0.zip) from the GitHub release. This ZIP is available for unpacked testing; it has not been submitted to the store listing.
  The native-host installer needs a source checkout and cannot discover a ZIP unpacked
  elsewhere, so pass the ID shown in `chrome://extensions`:
  `poetry run keyleak install-extension-host --extension-id <extension-id>`.
  Then reload KeyLeak in `chrome://extensions`.
- For local development, load the [`extension/`](../extension/) directory in
  `chrome://extensions`, then run `poetry run keyleak install-extension-host`
  from a source checkout. The helper restricts access to the exact extension
  origin.

The Web Store listing and the downloadable ZIP can have different versions because store
updates require a separate submission. See [release channels](DISTRIBUTION.md#chrome-web-store-is-a-separate-publication)
and the [extension privacy policy](../extension/PRIVACY_POLICY.md).
