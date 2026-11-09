"""Exercise the published bytes in a real browser at both Pages URL shapes.

All test inputs are synthetic. Network acquisition is mocked; no target sites
are scanned. CI installs the repository's pinned Playwright and Chromium first.
"""

from __future__ import annotations

import functools
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import zipfile

from playwright.sync_api import expect, sync_playwright

from scripts.build_browser_app import build_browser_app


ROOT = Path(__file__).resolve().parents[1]
CANARY = "sk-proj-" + "a" * 24
INPUT_TEXT = f'const apiKey = "{CANARY}";\n'


class BrowserAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="keyleak-browser-test-")
        cls.output = Path(cls.temporary.name) / "site"
        build_browser_app(ROOT, cls.output)
        cls.requests = []

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, _format, *_args):
                pass

            def do_GET(self):
                cls.requests.append({"method": "GET", "path": self.path})
                if self.path.startswith("/keyleak-detector/"):
                    self.path = self.path[len("/keyleak-detector"):]
                return super().do_GET()

            def do_POST(self):
                cls.requests.append({"method": "POST", "path": self.path})
                self.send_error(405)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(cls.output)))
        cls.server.daemon_threads = True
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.playwright = sync_playwright().start()
        launch = {"headless": True}
        # Optional local test runtime only; CI uses Playwright's pinned Chromium.
        if os.environ.get("KEYLEAK_TEST_CHROMIUM"):
            launch["executable_path"] = os.environ["KEYLEAK_TEST_CHROMIUM"]
        cls.browser = cls.playwright.chromium.launch(**launch)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)
        cls.temporary.cleanup()

    def context(self, **options):
        context = self.browser.new_context(accept_downloads=True, **options)
        self.addCleanup(context.close)
        return context

    def open(self, context, prefix="/keyleak-detector/"):
        page = context.new_page()
        page.goto(self.origin + prefix)
        expect(page.locator("#storage-state")).to_contain_text("50 redacted")
        return page

    def scan_text(self, page, text=INPUT_TEXT):
        page.get_by_role("tab", name="Text", exact=True).click()
        page.locator("#source-text").fill(text)
        page.locator("#scan-button").click()
        page.locator("#report-content").wait_for(state="visible", timeout=30000)

    def download(self, page, kind="json"):
        with page.expect_download() as download:
            page.locator(f'[data-export="{kind}"]').click()
        return Path(download.value.path()).read_text()

    def test_root_and_project_paths_scan_export_and_keep_inputs_off_network(self):
        for prefix in ("/", "/keyleak-detector/"):
            with self.subTest(prefix=prefix):
                context = self.context()
                requests = []
                errors = []
                context.on("request", lambda request: requests.append((request.url, request.method, request.post_data)))
                page = self.open(context, prefix)
                page.on("pageerror", lambda error: errors.append(str(error)))
                self.scan_text(page)
                report_text = self.download(page)
                report = json.loads(report_text)
                self.assertGreater(len(report["findings"]), 0)
                self.assertEqual(report["coverage"]["status"], "complete")
                self.assertNotIn(CANARY, report_text)
                self.assertNotIn('"raw_value":', report_text)
                self.assertNotIn(CANARY, page.locator("#report-content").inner_text())
                self.assertEqual(errors, [])
                self.assertTrue(all(urlsplit(url).netloc == urlsplit(self.origin).netloc for url, _, _ in requests))
                self.assertTrue(all(method == "GET" for _, method, _ in requests))
                self.assertTrue(all(CANARY not in str(request) for request in requests))
                self.assertTrue(all("/src/scan-worker.js" in url or "/src/" in url or "/engine/" in url or url.startswith(self.origin + prefix) for url, _, _ in requests))
                context.close()

    def test_redacted_history_survives_reload_and_can_be_deleted(self):
        context = self.context()
        page = self.open(context)
        self.scan_text(page)
        page.locator(".history-open").first.wait_for()
        saved = page.evaluate("""async () => {
          const module = await import('./src/storage.js');
          const store = await module.openReportStore();
          try { return await store.list(); } finally { store.close(); }
        }""")
        self.assertEqual(len(saved), 1)
        self.assertNotIn(CANARY, json.dumps(saved))
        page.reload()
        page.locator(".history-open").first.click()
        page.locator("#report-content").wait_for(state="visible")
        self.assertNotIn(CANARY, self.download(page))
        page.locator("#clear-history").click()
        expect(page.locator(".history-open")).to_have_count(0)

    def test_offline_reload_and_scan_use_only_cached_application_assets(self):
        context = self.context()
        page = self.open(context)
        expect(page.locator("#offline-state")).to_contain_text("Ready for offline", timeout=20000)
        page.evaluate("""() => new Promise((resolve, reject) => {
          if (navigator.serviceWorker.controller) { resolve(); return; }
          const timer = setTimeout(() => reject(new Error('No service worker controller')), 10000);
          navigator.serviceWorker.addEventListener('controllerchange', () => {
            clearTimeout(timer); resolve();
          }, {once: true});
        })""")
        context.set_offline(True)
        page.reload(wait_until="domcontentloaded")
        self.scan_text(page)
        self.assertGreater(len(json.loads(self.download(page))["findings"]), 0)
        cached = page.evaluate("""async () => {
          const keys = await caches.keys();
          return (await Promise.all(keys.map(async key => (await (await caches.open(key)).keys()).map(r => r.url)))).flat();
        }""")
        self.assertTrue(cached)
        self.assertTrue(all(url.startswith(self.origin + "/keyleak-detector/") for url in cached))
        self.assertFalse(any("php-check" in url or CANARY in url for url in cached))

    def test_zip_scans_members_but_unsupported_inputs_stay_incomplete(self):
        context = self.context()
        page = self.open(context)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("config.js", INPUT_TEXT)
        page.locator("#files").set_input_files({"name": "build.zip", "mimeType": "application/zip", "buffer": archive.getvalue()})
        page.locator("#scan-button").click()
        page.locator("#report-content").wait_for(state="visible")
        report = json.loads(self.download(page))
        self.assertEqual(report["coverage"]["status"], "complete")
        self.assertGreater(len(report["findings"]), 0)
        page.locator("#files").set_input_files({"name": "application.bin", "mimeType": "application/octet-stream", "buffer": b"\x00\x01\x02binary"})
        page.locator("#scan-button").click()
        expect(page.locator("#verdict-label")).to_contain_text("Incomplete")
        report = json.loads(self.download(page))
        self.assertTrue(report["coverage_incomplete"])
        self.assertNotEqual(report["verdict"]["status"], "SAFE_TO_SHIP")
        sarif = json.loads(self.download(page, "sarif"))
        self.assertFalse(sarif["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_cancelled_worker_does_not_save_or_show_a_successful_report(self):
        context = self.context(service_workers="block")
        context.route("**/src/scan-worker.js", lambda route: route.fulfill(content_type="application/javascript", body="self.onmessage = () => {};"))
        page = self.open(context)
        page.get_by_role("tab", name="Text", exact=True).click()
        page.locator("#source-text").fill(INPUT_TEXT)
        page.locator("#scan-button").click()
        page.locator("#cancel-button").click()
        self.assertTrue(page.locator("#report-content").is_hidden())
        self.assertEqual(page.locator("#report-state").inner_text(), "Canceled")
        self.assertEqual(page.locator(".history-open").count(), 0)
        self.assertTrue(page.locator("#scan-button").is_enabled())

    def test_mocked_url_acquisition_is_explicit_and_failures_are_not_clean(self):
        context = self.context(service_workers="block")
        observed = []
        def fulfill(route):
            observed.append(route.request)
            route.fulfill(content_type="text/javascript", headers={"Access-Control-Allow-Origin": "*"}, body=INPUT_TEXT)
        context.route("https://owned-resource.example.com/**", fulfill)
        page = self.open(context)
        page.get_by_role("tab", name="URL", exact=True).click()
        page.locator("#target-url").fill("https://owned-resource.example.com/bundle.js")
        page.locator("#scan-button").click()
        page.locator("#scan-error").wait_for(state="visible")
        self.assertEqual(observed, [])
        page.locator("#authorized").check()
        page.locator("#scan-button").click()
        page.locator("#report-content").wait_for(state="visible")
        self.assertEqual(len(observed), 1)
        report = json.loads(self.download(page))
        self.assertEqual(report["acquisition"]["method"], "direct-cors-fetch")
        self.assertNotIn("owned-resource.example.com", json.dumps(report))
        context.route("https://unavailable-resource.example.com/**", lambda route: route.abort("failed"))
        page.locator("#target-url").fill("https://unavailable-resource.example.com/bundle.js?secret=synthetic-private-value")
        page.locator("#scan-button").click()
        page.locator("#scan-error").wait_for(state="visible")
        self.assertTrue(page.locator("#report-content").is_hidden())
        self.assertNotIn("synthetic-private-value", page.locator("#scan-error").inner_text())
        self.assertEqual(page.locator("#report-state").inner_text(), "Incomplete")

    def test_mobile_layout_and_untrusted_text_rendering(self):
        context = self.context(viewport={"width": 390, "height": 844})
        page = self.open(context)
        page.locator("#files").set_input_files({"name": "<img src=x onerror=window.bad=true>.js", "mimeType": "text/javascript", "buffer": INPUT_TEXT.encode()})
        page.locator("#scan-button").click()
        page.locator("#report-content").wait_for(state="visible")
        self.assertFalse(page.evaluate("Boolean(window.bad)"))
        self.assertEqual(page.locator("#findings-list img").count(), 0)
        self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= innerWidth"))

    def test_dns_discovery_requires_consent_and_never_fetches_discovered_hosts(self):
        context = self.context(service_workers="block")
        queries = []
        external_requests = []
        context.on("request", lambda request: external_requests.append(request.url)
                   if urlsplit(request.url).netloc != urlsplit(self.origin).netloc else None)

        def resolve(route):
            query = parse_qs(urlsplit(route.request.url).query)
            hostname = query["name"][0]
            record_type = 1 if query["type"][0] == "A" else 28
            queries.append(hostname)
            answer = []
            if hostname == "api.example.com" and record_type == 1:
                answer.append({"name": hostname + ".", "type": 1, "TTL": 60, "data": "93.184.216.34"})
            body = {"Status": 0 if answer else 3, "TC": False,
                    "Question": [{"name": hostname + ".", "type": record_type}], "Answer": answer}
            route.fulfill(content_type="application/json", headers={"Access-Control-Allow-Origin": "*"}, body=json.dumps(body))

        context.route("https://dns.google/resolve?**", resolve)
        page = self.open(context)
        page.get_by_role("tab", name="Discovery", exact=True).click()
        page.locator("#target-domain").fill("example.com")
        page.locator("#scan-button").click()
        page.locator("#scan-error").wait_for(state="visible")
        self.assertEqual(queries, [])
        page.locator("#dns-authorized").check()
        page.locator("#scan-button").click()
        page.locator("#discovery-content").wait_for(state="visible")
        self.assertEqual(len(queries), 20)
        self.assertIn("api.example.com", page.locator("#discovery-list").inner_text())
        self.assertTrue(all(url.startswith("https://dns.google/resolve?") for url in external_requests))
        self.assertTrue(page.locator("#report-content").is_hidden())
        self.assertEqual(page.locator(".history-open").count(), 0)


if __name__ == "__main__":
    unittest.main()
