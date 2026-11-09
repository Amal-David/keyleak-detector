# KeyLeak in your browser

The browser app is a static site. Its detector runs in a Web Worker on the
visitor's device. Hosting serves the application files; it does not receive scan
inputs or run scans. No Python server, database service, WebContainer, browser
extension, or WebAssembly runtime is required for this version.

The app reuses the extension's JavaScript detector. It is a separate browser
entrypoint, not a port of every Python CLI capability.

## Supported in this version

| Input or operation | Behavior |
| --- | --- |
| Pasted text | Analyze in the browser worker. |
| Local files or a selected folder | Read selected UTF-8 text files on this device and analyze their contents. Binary and non-UTF-8 inputs produce coverage gaps. Folder selection depends on browser support; individual files remain available. |
| ZIP archive | Inspect stored or deflated UTF-8 text entries locally, with limits on archive size and expansion. Nested, encrypted and ZIP64 archives are not expanded. |
| Source maps | Reconstruct embedded `sourcesContent` from flat version 3 source maps. Indexed sections and nested reconstruction produce coverage gaps. External source URLs are never fetched. |
| A single HTTPS resource URL | Fetch one supported text response only after the user requests it, then analyze the readable body. The remote server must permit cross-origin access. Redirects are refused; credentials and referrers are omitted. |
| Subdomain candidates | On explicit request, query Google's DNS-over-HTTPS service for a bounded list of common names under the supplied domain, with wildcard checks. This sends the queried names to Google. |
| Findings, exports and saved history | Produce redacted results locally; report exports are files on the user's device. Up to 50 reports are saved in this browser by default; uncheck **Save redacted reports locally** to stop saving new reports. |
| Offline local scanning | After the application has finished caching successfully, reopen it and scan local inputs without network access. |

An inaccessible URL or unsupported archive is reported as incomplete coverage;
it must not be interpreted as a clean scan. Findings identify potential exposed
secrets; this mode does not verify their validity with providers.

The browser includes a narrow adapter for the registered OTP/verification-code
pattern's 4–8-character captures, which the shared analyzer's generic short-value
filter otherwise excludes. These findings remain unverified leads: an OTP-like
field in source code, a fixture, or an example does not demonstrate a live
authentication exposure or bypass. This adapter does not change the extension
or claim parity with the Python checks.

This version does not crawl arbitrary websites, run Playwright or native CLI
tools, open TCP/UDP sockets, run the Python active BaaS checks, or bridge to the
Chrome extension. DNS candidate checks are not complete subdomain enumeration.

## Default limits and coverage

These are the defaults used by the app. Analysis stops or records a coverage gap
when a bound is reached; unavailable content is never counted as a clean scan.

| Operation or budget | Default |
| --- | --- |
| One text file or reconstructed source | 2 MiB |
| Total selected input, including compressed ZIP bytes | 20 MiB |
| Total analyzed/expanded text, including reconstructed sources | 40 MiB |
| Combined files, archive members, and reconstructed entries | 500 entries |
| Findings | 50 per text input; 500 across the scan |
| ZIP expansion | Stored/deflate only; at most 100:1 per member; no nested expansion |
| Source-map reconstruction | One level of embedded originals |
| Analysis time | 20-second cooperative engine limit; the UI terminates its worker after 25 seconds |
| One HTTPS acquisition | 2 MiB of streamed response bytes; 15-second deadline |
| DNS discovery | Eight common labels, each queried for A and AAAA, plus two randomized wildcard-control names: 20 requests total, at most two in parallel |
| DNS deadlines | Eight seconds per request; 45 seconds for the operation |
| Saved history | Up to 50 reports in this browser |

ZIP entries are read as bytes without writing extracted files to disk. Unsafe
paths, symlinks, conflicting records, unreferenced local payloads, invalid
checksums, encrypted entries and unsupported formats result in incomplete
coverage. The browser must support `DecompressionStream('deflate-raw')` to read
deflated members; otherwise those archives produce an explicit coverage gap.

DNS observations stay in page memory and are not saved as scan reports. A
resolving candidate is not proof of a distinct service, particularly when the
wildcard checks detect wildcard DNS or remain inconclusive. The app does not
fetch any discovered host. HTTPS acquisition blocks known local, private,
metadata and special-use literal hosts, but browser Fetch cannot inspect or pin
the connected IP address. These checks do not guarantee that a DNS hostname
resolves to a public address.

## Data flow and privacy

Local text, file and ZIP scans do not upload their inputs or findings. No
analytics or remote secret-validation endpoint is included in this app. Direct
URL acquisition necessarily sends a request to the selected host, and optional
DNS-over-HTTPS acquisition sends names to the resolver. Those third parties can
observe their respective requests. There is no fallback public CORS proxy.

The static host can observe normal application downloads, such as the visitor's
IP address and requested application asset paths. Browser execution does not
remove the need to trust the application code and its updates. Browser storage
is also subject to the user's browser profile, other same-origin code, quotas,
clearing and eviction. Keep an exported copy of findings that must be retained.

Detected credential evidence is replaced with `[redacted]`, and source snippets
and input file contents are omitted from reports and history. Reports retain
bounded source labels, including ordinary relative paths, to identify affected
files. Those labels are filtered heuristically: filenames and project or user
names can still be sensitive metadata. Reports are not anonymized, so review
source labels before sharing an export. Acquired URLs use a generic source label
and are not saved in reports. Use **Clear all** to remove saved reports; the
current input and report remain in page memory until the page is closed or
reloaded.

On GitHub Pages, `/keyleak-detector/` is a path under
`https://amal-david.github.io`, not a separate security origin. Database/cache
namespaces prevent accidental collisions; they do not protect data from other
applications on that same origin. A dedicated custom hostname is the better
deployment for stronger separation from unrelated hosted projects.

The service worker caches an explicit list of application assets only. Acquired
target responses, local scan inputs and exported findings are not placed in that
offline application cache. Closing the page stops its worker; reopen the page to
start another scan. The app does not promise unattended background scans.

## Build and preview

Requirements: Python 3.12+ for the standard-library-only build, and a current
browser for the application. Node.js is needed only for JavaScript tests.

```bash
python scripts/build_browser_app.py
python -m http.server 8080 --directory dist/browser
```

Open `http://localhost:8080/`. The local preview server only serves static files;
it is not a scanner backend. Service workers require HTTPS in production, with
localhost available for development. Opening `index.html` directly through a
`file:` URL is not supported.

The build outputs `dist/browser/` and can also write to an empty temporary
directory through `--output PATH`. It copies only the intended application
entrypoints, runtime JavaScript and four shared detector modules. It excludes
tests, dependencies, Python source, credentials and scan reports. A content hash
versions the offline asset list and service worker cache.

The existing PHP configuration checker is preserved at `php-check/`, and its
existing favicon is included. That checker retains its separate behavior; it is
not part of the browser scanner's offline asset cache.

All application URLs are relative. The same generated files can be served at:

- `https://amal-david.github.io/keyleak-detector/` (project Pages).
- The root of a dedicated custom domain.
- A local static server for development.

No custom COOP/COEP headers or SharedArrayBuffer support are needed. The build
does not generate a `CNAME` file or change domain settings.

## Publish through GitHub Pages

The workflow is `.github/workflows/browser-pages.yml`.

1. In the repository, open **Settings → Pages**.
2. Under **Build and deployment → Source**, select **GitHub Actions**. This is a
   one-time repository setting; the workflow intentionally does not enable it
   using a token with extra administration privileges.
3. Merge the browser app into `main`. A successful main-branch run builds, tests
   and publishes `dist/browser/`. Alternatively, run **Browser app and Pages**
   manually from the Actions tab while selecting `main`.
4. Open the URL reported by the **Publish to GitHub Pages** job. For the default
   project domain it is `https://amal-david.github.io/keyleak-detector/`.

Pull requests build and test only. Only the separate deployment job receives
`pages: write` and `id-token: write`; it runs only for a push or manual run on
`main`, using the `github-pages` environment. Build steps have a read-only token,
no repository secrets and no persisted checkout credentials. Top-level actions
are pinned to verified commit SHAs. Set environment protection rules according
to the repository's release policy.

The deployment replaces the Pages site's files, so the artifact includes the
existing `php-check/` utility. Additional Pages content should be explicitly
added to the build's publication list before it is introduced.

GitHub documents the [publishing-source setting](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
and [custom-workflow permissions](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
Any custom domain remains configured through repository Pages settings and DNS.

## Verification

```bash
node --test web/tests/*.test.js
python -m unittest discover -s web/tests -p 'test_*.py' -v
python -m pip install "playwright==1.63.0"
python -m playwright install chromium
python -m unittest tests.test_browser_app -v
```

The publication tests check the build's allowlist, unchanged PHP checker,
reproducibility, cache invalidation, symlink rejection and protection of
unrelated output directories. Chromium integration checks exercise the built
artifact under both root and project paths, including local scanning, reports,
history and offline use. The Pages workflow runs these checks before publishing.
