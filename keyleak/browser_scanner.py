"""Headless-browser CI runner (Wave 2.4).

Loads a URL via Playwright Chromium with the KeyLeak analyzer injected as a
plain JavaScript library (no MV3 host, no ``--load-extension``). The injected
script enumerates DOM, ``localStorage``, ``sessionStorage``, IndexedDB, and
Cache Storage, runs the same detector patterns the CLI uses, and returns the
findings via ``page.evaluate(...)``.

Wave 4.1 adds BaaS extraction and active validation: after pattern scanning,
the injected script extracts BaaS configuration (Supabase URL, anon key, table
names, RPC functions, storage buckets) and Python-side probes confirm whether
RLS policies are enforced.

Why this shape:
- Wave-1 fork resolved that the consumer Chrome extension sunsets. The
  ``extension/lib/analyzer.js`` and ``extension/lib/patterns.js`` modules
  remain as the shared engine, reused here in CI.
- The ``page.addInitScript`` path sidesteps Chrome 130's expected deprecation
  of ``--load-extension`` in headless. We never load an MV3 host.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .detectors import detectors_for_packs, normalize_packs
from .extension_bundle import extension_pattern_payload
from .local_scanner import scan_text
from .models import Evidence, Finding, ScanReport
from .proxy import playwright_proxy
from .redaction import new_run_salt, redact_url, redact_value, stable_id
from .reporting import build_report


_LOG = logging.getLogger(__name__)

SCAN_BUDGET_DEFAULT_SECONDS = 30
DEFAULT_VIEWPORT = {"width": 1280, "height": 1024}
CDP_MAX_BODY_BYTES = 2 * 1024 * 1024
CDP_MAX_TOTAL_BUFFER_BYTES = 10 * 1024 * 1024
CDP_TEXT_HINTS = (
    "text/",
    "json",
    "javascript",
    "ecmascript",
    "xml",
    "x-www-form-urlencoded",
    "graphql",
    "source-map",
)


# The init script we inject into the page context. It exposes a global
# ``__keyleak_findings`` populated by the analyzer; ``run_browser_scan`` reads
# it back after the page settles. Patterns are inlined at injection time so
# the page doesn't need network access to load them.
_INIT_SCRIPT_TEMPLATE = r"""
(function () {
  if (typeof window === 'undefined') return;
  if (window.__keyleak_initialized) return;
  window.__keyleak_initialized = true;
  window.__keyleak_findings = [];

  const PATTERNS = __PATTERNS__;
  const compiled = PATTERNS.map(function (p) {
    try {
      return Object.assign({}, p, {regex: new RegExp(p.pattern, p.flags)});
    } catch (err) {
      return null;
    }
  }).filter(Boolean);

  function emit(detector, source, value, where) {
    window.__keyleak_findings.push({
      detector_id: detector.detector_id,
      type: detector.finding_type || detector.id,
      severity: detector.severity,
      source: source,
      value: String(value).slice(0, 240),
      where: where,
    });
  }

  function scanString(text, source) {
    if (!text || typeof text !== 'string') return;
    for (let i = 0; i < compiled.length; i++) {
      const d = compiled[i];
      const m = text.match(d.regex);
      if (m) {
        emit(d, source, m[0], 'string');
      }
    }
  }

  async function scanIndexedDB() {
    if (!('indexedDB' in window) || typeof indexedDB.databases !== 'function') return;
    try {
      const dbs = await indexedDB.databases();
      for (const dbInfo of dbs || []) {
        if (!dbInfo || !dbInfo.name) continue;
        await new Promise(function (resolve) {
          const req = indexedDB.open(dbInfo.name);
          req.onerror = function () { resolve(); };
          req.onsuccess = function () {
            const db = req.result;
            const stores = Array.from(db.objectStoreNames || []);
            if (!stores.length) { db.close(); resolve(); return; }
            const tx = db.transaction(stores, 'readonly');
            let remaining = stores.length;
            stores.forEach(function (storeName) {
              const store = tx.objectStore(storeName);
              const getAll = store.getAll();
              getAll.onsuccess = function () {
                const rows = getAll.result || [];
                for (const row of rows) {
                  scanString(JSON.stringify(row), `indexeddb:${dbInfo.name}/${storeName}`);
                }
                if (--remaining === 0) { db.close(); resolve(); }
              };
              getAll.onerror = function () {
                if (--remaining === 0) { db.close(); resolve(); }
              };
            });
          };
        });
      }
    } catch (_err) { /* swallow */ }
  }

  async function scanCacheStorage() {
    if (!('caches' in window)) return;
    try {
      const names = await caches.keys();
      for (const name of names) {
        const cache = await caches.open(name);
        const requests = await cache.keys();
        for (const req of requests) {
          const resp = await cache.match(req);
          if (!resp) continue;
          try {
            const text = await resp.clone().text();
            scanString(text, `cache:${name}/${req.url}`);
          } catch (_e) { /* binary body */ }
        }
      }
    } catch (_err) { /* swallow */ }
  }

  async function scanServiceWorkers() {
    if (!('serviceWorker' in navigator)) return;
    try {
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const r of regs || []) {
        const sw = r.active || r.waiting || r.installing;
        const scriptURL = sw && sw.scriptURL;
        if (scriptURL) {
          window.__keyleak_findings.push({
            detector_id: 'browser.service_worker_registration',
            type: 'service_worker_registration',
            severity: 'info',
            source: scriptURL,
            value: r.scope,
            where: 'service-worker',
          });
        }
      }
    } catch (_err) { /* swallow */ }
  }

  function scanDom() {
    scanString(document.documentElement.outerHTML, 'document');
    for (let i = 0; i < localStorage.length; i++) {
      var key = localStorage.key(i);
      var value = localStorage.getItem(key);
      scanString(key + '=' + value, 'localStorage:' + key);
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      var key = sessionStorage.key(i);
      var value = sessionStorage.getItem(key);
      scanString(key + '=' + value, 'sessionStorage:' + key);
    }
  }

  window.__keyleak_run = async function () {
    scanDom();
    await scanIndexedDB();
    await scanCacheStorage();
    await scanServiceWorkers();
    return window.__keyleak_findings;
  };

  // Frontend dependency hygiene — report the versions of well-known libraries
  // the page actually loaded, so Python can flag known-vulnerable releases.
  // Reads runtime version globals first, then falls back to parsing the version
  // out of <script src> filenames for libraries not exposed as globals.
  window.__keyleak_library_scan = function () {
    var libs = [];
    try {
      if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
        libs.push({name: 'jquery', version: window.jQuery.fn.jquery, source: 'global'});
      } else if (window.$ && window.$.fn && window.$.fn.jquery) {
        libs.push({name: 'jquery', version: window.$.fn.jquery, source: 'global'});
      }
      if (window.bootstrap && (window.bootstrap.Tooltip || window.bootstrap.Alert)) {
        libs.push({name: 'bootstrap', version: (window.bootstrap.Tooltip || window.bootstrap.Alert).VERSION, source: 'global'});
      } else if (window.jQuery && window.jQuery.fn && window.jQuery.fn.tooltip && window.jQuery.fn.tooltip.Constructor) {
        // Bootstrap 4 registers as a jQuery plugin exposing Constructor.VERSION.
        libs.push({name: 'bootstrap', version: window.jQuery.fn.tooltip.Constructor.VERSION, source: 'global'});
      }
      if (window.React && window.React.version) {
        libs.push({name: 'react', version: window.React.version, source: 'global'});
      }
      if (window.Vue && window.Vue.version) {
        libs.push({name: 'vue', version: window.Vue.version, source: 'global'});
      }
      if (window.angular && typeof window.angular.version === 'object' && window.angular.version.full) {
        libs.push({name: 'angular', version: window.angular.version.full, source: 'global'});
      }
      var SRC_RE = [
        ['jquery', /jquery[-.]?(\d+\.\d+\.\d+)/i],
        ['bootstrap', /bootstrap[-.]?(\d+\.\d+\.\d+)/i],
        ['angular', /angular[-.]?(\d+\.\d+\.\d+)/i]
      ];
      var srcs = document.querySelectorAll('script[src]');
      for (var i = 0; i < srcs.length; i++) {
        var src = srcs[i].src || '';
        for (var j = 0; j < SRC_RE.length; j++) {
          var m = SRC_RE[j][1].exec(src);
          if (m) libs.push({name: SRC_RE[j][0], version: m[1], source: 'script-url', url: src});
        }
      }
    } catch (_err) { /* swallow — best-effort enumeration */ }
    return libs;
  };

  // Wave 4.1 — BaaS config extraction.
  // Fetches all JS bundles loaded by the page and extracts Supabase/Firebase
  // configuration: project URL, anon key, table names, RPC functions, and
  // storage buckets.
  window.__keyleak_baas_extract = async function () {
    var result = {
      supabase_url: null,
      supabase_key: null,
      tables: [],
      rpcs: [],
      buckets: []
    };

    // Collect all text: inline scripts + fetched external bundles
    var texts = [];
    var scripts = document.querySelectorAll('script');
    for (var i = 0; i < scripts.length; i++) {
      if (scripts[i].textContent) texts.push(scripts[i].textContent);
    }

    // Fetch external script sources (same-origin or CORS-allowed)
    var srcScripts = document.querySelectorAll('script[src], link[rel="modulepreload"]');
    for (var i = 0; i < srcScripts.length; i++) {
      var src = srcScripts[i].src || srcScripts[i].href;
      if (!src) continue;
      try {
        var resp = await fetch(src, {cache: 'force-cache'});
        if (resp.ok) {
          var text = await resp.text();
          if (text.length < 5000000) texts.push(text);
        }
      } catch (_e) { /* cross-origin or network error */ }
    }

    var allText = texts.join('\n');

    // Extract Supabase URL
    var urlRe = /https:\/\/[a-z0-9]{20,}\.supabase\.co/g;
    var m = urlRe.exec(allText);
    if (m) result.supabase_url = m[0];

    // Extract Supabase key — look near the URL or createClient calls
    // JWT format
    var jwtRe = /eyJ[A-Za-z0-9_-]{30,}\.eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}/g;
    // sb_publishable_ format
    var pubRe = /sb_publishable_[A-Za-z0-9_-]{20,}/g;

    m = pubRe.exec(allText);
    if (m) {
      result.supabase_key = m[0];
    } else {
      // Only use JWT if we have a Supabase URL (to avoid false positives)
      if (result.supabase_url) {
        // Look near the URL for the key
        var urlIdx = allText.indexOf(result.supabase_url);
        if (urlIdx >= 0) {
          var nearby = allText.substring(urlIdx, Math.min(urlIdx + 1000, allText.length));
          m = jwtRe.exec(nearby);
          if (m) result.supabase_key = m[0];
        }
      }
    }

    // Extract .from("table_name") calls
    var fromRe = /\.from\(["']([a-z_][a-z0-9_]{1,62})["']\)/g;
    while ((m = fromRe.exec(allText)) !== null) {
      if (result.tables.indexOf(m[1]) === -1) result.tables.push(m[1]);
    }

    // Extract .rpc("fn_name") calls
    var rpcRe = /\.rpc\(["']([a-z_][a-z0-9_]{1,62})["']/g;
    while ((m = rpcRe.exec(allText)) !== null) {
      if (result.rpcs.indexOf(m[1]) === -1) result.rpcs.push(m[1]);
    }

    // Extract .storage.from("bucket_name") calls
    var bucketRe = /\.storage\.from\(["']([a-z0-9_-]{1,62})["']\)/g;
    while ((m = bucketRe.exec(allText)) !== null) {
      if (result.buckets.indexOf(m[1]) === -1) result.buckets.push(m[1]);
    }

    // Firebase config extraction
    var firebaseConfigRe = /firebase[Cc]onfig\s*=?\s*\{[^}]*apiKey\s*:\s*["']([^"']+)["'][^}]*databaseURL\s*:\s*["']([^"']+)["'][^}]*(?:storageBucket\s*:\s*["']([^"']+)["'])?/;
    var fbm = firebaseConfigRe.exec(allText);
    if (fbm) {
      result.firebase_api_key = fbm[1];
      result.firebase_db_url = fbm[2];
      if (fbm[3]) result.firebase_storage_bucket = fbm[3];
    } else {
      // Try individual patterns
      var dbUrlRe = /https:\/\/[a-z0-9-]+\.firebaseio\.com/g;
      var dbm = dbUrlRe.exec(allText);
      if (dbm) result.firebase_db_url = dbm[0];

      var aizaRe = /AIza[0-9A-Za-z_-]{35}/g;
      var aim = aizaRe.exec(allText);
      if (aim) result.firebase_api_key = aim[0];

      var bucketRe2 = /[a-z0-9-]+\.appspot\.com/g;
      var bm = bucketRe2.exec(allText);
      if (bm) result.firebase_storage_bucket = bm[0];
    }

    // Appwrite
    var awEndpointRe = /\.setEndpoint\(["'](https?:\/\/[^"']+\/v1)["']\)/;
    var awProjectRe = /\.setProject\(["']([^"']+)["']\)/;
    var awm = awEndpointRe.exec(allText);
    if (awm) {
      result.appwrite_endpoint = awm[1];
      var awp = awProjectRe.exec(allText);
      if (awp) result.appwrite_project = awp[1];
    }

    // PocketBase
    var pbRe = /new PocketBase\(["'](https?:\/\/[^"']+)["']\)/;
    var pbm = pbRe.exec(allText);
    if (pbm) result.pocketbase_url = pbm[1];

    // Realtime channels
    var channelRe = /\.channel\(["']([^"']+)["']\)/g;
    result.realtime_channels = [];
    while ((m = channelRe.exec(allText)) !== null) {
      if (result.realtime_channels.indexOf(m[1]) === -1) result.realtime_channels.push(m[1]);
    }

    return result;
  };
})();
"""


def _build_init_script(payload: Optional[List[Dict[str, Any]]] = None) -> str:
    payload = payload if payload is not None else extension_pattern_payload()
    encoded = json.dumps(payload)
    return _INIT_SCRIPT_TEMPLATE.replace("__PATTERNS__", encoded)


def _browser_detectors():
    packs = normalize_packs(None, profile="launch-gate", surface="extension")
    return detectors_for_packs(packs, extension_only=True)


def _is_http_url(url: object) -> bool:
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    return parsed.scheme in {"http", "https", "ws", "wss"} and bool(parsed.netloc)


def _is_text_mime(mime_type: object, headers: Optional[Dict[str, Any]] = None) -> bool:
    content_type = str(mime_type or "")
    if not content_type and headers:
        content_type = str(_header_value(headers, "content-type") or "")
    if not content_type:
        return True
    lowered = content_type.lower()
    return any(hint in lowered for hint in CDP_TEXT_HINTS)


def _header_value(headers: Optional[Dict[str, Any]], name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _content_length_too_large(headers: Optional[Dict[str, Any]]) -> bool:
    raw = _header_value(headers, "content-length")
    if not raw:
        return False
    try:
        return int(raw) > CDP_MAX_BODY_BYTES
    except ValueError:
        return False


def _decode_cdp_body(payload: Dict[str, Any]) -> str:
    body = payload.get("body")
    if not isinstance(body, str) or not body:
        return ""
    if payload.get("base64Encoded"):
        try:
            raw = base64.b64decode(body, validate=False)
        except Exception:
            return ""
        if len(raw) > CDP_MAX_BODY_BYTES:
            return ""
        return raw.decode("utf-8", errors="ignore")
    if len(body.encode("utf-8", errors="ignore")) > CDP_MAX_BODY_BYTES:
        return ""
    return body


def _cdp_send(cdp: Any, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    params = params or {}
    try:
        return cdp.send(method, params)
    except TypeError:
        return cdp.send(method, **params)


class _CdpNetworkCapture:
    """Best-effort CDP capture for Playwright Chromium scans."""

    def __init__(self, cdp: Any, target_url: str, run_salt: bytes):
        self.cdp = cdp
        self.target_url = target_url
        self.run_salt = run_salt
        self.requests: Dict[str, Dict[str, Any]] = {}
        self._findings: List[Finding] = []
        self._detectors = _browser_detectors()

    def start(self) -> None:
        _cdp_send(
            self.cdp,
            "Network.enable",
            {
                "maxTotalBufferSize": CDP_MAX_TOTAL_BUFFER_BYTES,
                "maxResourceBufferSize": CDP_MAX_BODY_BYTES,
            },
        )
        for domain in ("Runtime.enable", "Log.enable"):
            try:
                _cdp_send(self.cdp, domain)
            except Exception as exc:
                _LOG.debug("CDP domain enable failed for %s: %s", domain, exc, exc_info=True)

        self.cdp.on("Network.requestWillBeSent", self._on_request)
        self.cdp.on("Network.responseReceived", self._on_response)
        self.cdp.on("Network.loadingFinished", self._on_loading_finished)
        self.cdp.on("Network.loadingFailed", self._on_loading_failed)
        self.cdp.on("Network.webSocketCreated", self._on_websocket_created)
        self.cdp.on("Network.webSocketClosed", self._on_websocket_closed)
        self.cdp.on("Network.webSocketFrameSent", self._on_websocket_frame)
        self.cdp.on("Network.webSocketFrameReceived", self._on_websocket_frame)
        self.cdp.on("Runtime.consoleAPICalled", self._on_console)
        self.cdp.on("Log.entryAdded", self._on_log_entry)

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings)

    def detach(self) -> None:
        try:
            self.cdp.detach()
        except Exception as exc:
            _LOG.debug("CDP detach failed: %s", exc, exc_info=True)

    def _scan_text(
        self,
        text: object,
        source: str,
        request_url: str,
        *,
        response_status: Optional[int] = None,
    ) -> None:
        if not isinstance(text, str) or not text or not _is_http_url(request_url):
            return
        if len(text.encode("utf-8", errors="ignore")) > CDP_MAX_BODY_BYTES:
            return
        for finding in scan_text(text, source, self._detectors, run_salt=self.run_salt):
            finding.evidence.request_url = redact_url(request_url)
            if response_status is not None:
                finding.evidence.response_status = response_status
            finding.id = stable_id(
                finding.type,
                finding.detector_id,
                finding.source,
                finding.evidence.redacted_value,
                finding.evidence.line,
                finding.evidence.request_url,
            )
            self._findings.append(finding)

    def _remember(self, request_id: str, **updates: Any) -> Dict[str, Any]:
        record = self.requests.setdefault(request_id, {})
        for key, value in updates.items():
            if value not in (None, ""):
                record[key] = value
        return record

    def _on_request(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        request = params.get("request") or {}
        url = str(request.get("url") or "")
        if not request_id or not _is_http_url(url):
            return
        headers = request.get("headers") or {}
        post_data = request.get("postData") or ""
        self._remember(
            request_id,
            url=url,
            request_headers=headers,
            method=request.get("method"),
        )

        safe_url = redact_url(url)
        self._scan_text(url, f"CDP Request URL: {safe_url}", url)
        if headers:
            header_text = "\n".join(f"{name}: {value}" for name, value in headers.items())
            self._scan_text(header_text, f"CDP Request Headers: {safe_url}", url)
        if post_data:
            self._scan_text(str(post_data), f"CDP Request Body: {safe_url}", url)

    def _on_response(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        response = params.get("response") or {}
        url = str(response.get("url") or "")
        if not request_id or not _is_http_url(url):
            return
        headers = response.get("headers") or {}
        status = response.get("status")
        self._remember(
            request_id,
            url=url,
            response_headers=headers,
            response_status=status,
            mime_type=response.get("mimeType"),
        )
        safe_url = redact_url(url)
        if headers:
            header_text = "\n".join(f"{name}: {value}" for name, value in headers.items())
            self._scan_text(
                header_text,
                f"CDP Response Headers: {safe_url}",
                url,
                response_status=status if isinstance(status, int) else None,
            )

    def _on_loading_finished(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        record = self.requests.get(request_id) or {}
        url = str(record.get("url") or "")
        headers = record.get("response_headers") or {}
        status = record.get("response_status")
        try:
            if not url or not _is_text_mime(record.get("mime_type"), headers):
                return
            if _content_length_too_large(headers):
                return

            try:
                payload = _cdp_send(self.cdp, "Network.getResponseBody", {"requestId": request_id})
            except Exception as exc:
                _LOG.debug("CDP response body unavailable for %s: %s", request_id, exc, exc_info=True)
                return
            body = _decode_cdp_body(payload)
            self._scan_text(
                body,
                f"CDP Response Body: {redact_url(url)}",
                url,
                response_status=status if isinstance(status, int) else None,
            )
        finally:
            if urlparse(url).scheme.lower() in {"http", "https"}:
                self.requests.pop(request_id, None)

    def _on_loading_failed(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        record = self.requests.get(request_id) or {}
        url = str(record.get("url") or "")
        if urlparse(url).scheme.lower() in {"http", "https"}:
            self.requests.pop(request_id, None)

    def _on_websocket_created(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        url = str(params.get("url") or "")
        if request_id and _is_http_url(url):
            self._remember(request_id, url=url, mime_type="text/plain")

    def _on_websocket_closed(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        if request_id:
            self.requests.pop(request_id, None)

    def _on_websocket_frame(self, params: Dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        record = self.requests.get(request_id) or {}
        url = str(record.get("url") or self.target_url)
        response = params.get("response") or {}
        payload = response.get("payloadData")
        opcode = response.get("opcode")
        if opcode is not None and opcode not in (1, "1"):
            return
        self._scan_text(str(payload or ""), f"CDP WebSocket Frame: {redact_url(url)}", url)

    def _on_console(self, params: Dict[str, Any]) -> None:
        values: List[str] = []
        for arg in params.get("args") or []:
            if "value" in arg:
                values.append(str(arg.get("value")))
            elif "description" in arg:
                values.append(str(arg.get("description")))
        if values:
            level = str(params.get("type") or "console")
            self._scan_text("\n".join(values), f"CDP Console {level}", self.target_url)

    def _on_log_entry(self, params: Dict[str, Any]) -> None:
        entry = params.get("entry") or {}
        text = entry.get("text")
        if text:
            level = str(entry.get("level") or "log")
            url = str(entry.get("url") or self.target_url)
            self._scan_text(str(text), f"CDP Log {level}", url)


def _start_cdp_capture(context: Any, page: Any, target_url: str, run_salt: bytes) -> Optional[_CdpNetworkCapture]:
    try:
        cdp = context.new_cdp_session(page)
    except Exception as exc:
        _LOG.debug("CDP session attach failed: %s", exc, exc_info=True)
        return None
    capture = _CdpNetworkCapture(cdp, target_url, run_salt)
    try:
        capture.start()
    except Exception as exc:
        _LOG.debug("CDP capture start failed: %s", exc, exc_info=True)
        capture.detach()
        return None
    return capture


def run_browser_scan(
    url: str,
    *,
    auth_state_path: Optional[str] = None,
    scan_budget_seconds: int = SCAN_BUDGET_DEFAULT_SECONDS,
    headless: bool = True,
    baas_validate: bool = False,
    baas_prober: Optional[Any] = None,
    baas_tables: Optional[List[str]] = None,
    proxy: Optional[str] = None,
) -> ScanReport:
    """Drive Playwright Chromium, inject the analyzer, return a ScanReport.

    Raises ``ImportError`` if Playwright is not installed. When ``proxy`` is set,
    both the browser and BaaS validation probes route through it.
    """

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "keyleak browser-scan requires Playwright. "
            "Install with `pip install playwright && python -m playwright install chromium`."
        ) from exc

    init_script = _build_init_script()
    run_salt = new_run_salt()
    cdp_capture: Optional[_CdpNetworkCapture] = None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, proxy=playwright_proxy(proxy))
        context_kwargs: Dict[str, Any] = {"viewport": DEFAULT_VIEWPORT}
        if auth_state_path:
            context_kwargs["storage_state"] = auth_state_path
        context = browser.new_context(**context_kwargs)
        context.add_init_script(init_script)

        page = context.new_page()
        page.set_default_timeout(scan_budget_seconds * 1000)
        cdp_capture = _start_cdp_capture(context, page, url, run_salt)
        page.goto(url, wait_until="networkidle")
        raw = page.evaluate("() => window.__keyleak_run ? window.__keyleak_run() : []")

        # Always extract BaaS config (tables, RPCs, buckets) for pattern-based
        # detection.  Active validation probes are gated by baas_validate.
        baas_extraction = None
        try:
            baas_extraction = page.evaluate(
                "() => window.__keyleak_baas_extract ? window.__keyleak_baas_extract() : null"
            )
        except Exception:
            pass

        # Enumerate loaded frontend libraries + versions for CVE matching.
        libraries = []
        try:
            libraries = page.evaluate(
                "() => window.__keyleak_library_scan ? window.__keyleak_library_scan() : []"
            )
        except Exception:
            pass

        cdp_findings = cdp_capture.findings if cdp_capture else []
        if cdp_capture:
            cdp_capture.detach()
        browser.close()

    # Merge extra --baas-tables into extraction
    if baas_tables and baas_extraction:
        existing = set(baas_extraction.get("tables") or [])
        for t in baas_tables:
            if t not in existing:
                baas_extraction.setdefault("tables", []).append(t)
    elif baas_tables and not baas_extraction:
        baas_extraction = {"tables": list(baas_tables), "rpcs": [], "buckets": []}

    findings = [_to_finding(entry, url, run_salt) for entry in raw or []]
    findings.extend(cdp_findings)
    baas_findings = _run_baas_validation(raw, baas_extraction, baas_validate, baas_prober, proxy)
    findings.extend(baas_findings)

    from .js_library_cves import _library_cve_findings
    findings.extend(_library_cve_findings(libraries or [], url))

    return build_report(
        url,
        findings,
        scan_mode="browser",
        profile="launch-gate",
        packs=["leak", "appsec", "access-control", "baas"],
    )


def _run_baas_validation(
    raw_findings: Optional[List[Dict[str, Any]]],
    baas_extraction: Optional[Dict[str, Any]],
    baas_validate: bool,
    baas_prober: Optional[Any],
    proxy: Optional[str] = None,
) -> List[Finding]:
    if not baas_validate:
        return []

    from .baas_validator import extract_baas_config, make_default_prober, validate_baas_config

    config = extract_baas_config(raw_findings, baas_extraction)
    if config is None:
        return []

    # Route validation probes through the same proxy as the browser, unless the
    # caller injected its own prober (tests do this).
    if baas_prober is None and proxy:
        baas_prober = make_default_prober(proxy)

    validation = validate_baas_config(config, prober=baas_prober, js_extraction=baas_extraction)
    return validation.findings


def _to_finding(entry: Dict[str, Any], target: str, run_salt: Optional[bytes] = None) -> Finding:
    source = entry.get("source") or target
    value = str(entry.get("value") or "")
    # Redact before the value ever leaves this process. The browser path used to
    # store the raw match in ``redacted_value``/``snippet``, leaking cleartext
    # secrets into reports, CI artifacts, and the /scan JSON response. Always use
    # salted (HMAC) redaction — never the partial prefix/suffix masking — so a
    # caller that forgets to pass a salt can't leak secret fragments.
    if run_salt is None:
        run_salt = new_run_salt()
    redacted = redact_value(value, run_salt=run_salt)
    evidence = Evidence(
        source=source,
        snippet=redacted,
        redacted_value=redacted,
        request_url=target,
    )
    detector_id = str(entry.get("detector_id") or "browser:unknown")
    return Finding(
        type=str(entry.get("type") or detector_id),
        severity=str(entry.get("severity") or "info"),
        confidence=0.85,
        detector_id=detector_id,
        source=source,
        evidence=evidence,
        risk_reason=f"Browser-side scan detected {detector_id}",
        remediation="Rotate the exposed credential and remove it from the bundle / storage.",
        validation_status="lead",
        category="leak",
    )


# Exposed for testing without launching a real browser.
def evaluate_findings_payload(
    raw_findings: List[Dict[str, Any]],
    target_url: str,
    baas_extraction: Optional[Dict[str, Any]] = None,
    *,
    baas_validate: bool = False,
    baas_prober: Optional[Any] = None,
) -> ScanReport:
    run_salt = new_run_salt()
    findings = [_to_finding(entry, target_url, run_salt) for entry in raw_findings or []]
    baas_findings = _run_baas_validation(raw_findings, baas_extraction, baas_validate, baas_prober)
    findings.extend(baas_findings)
    return build_report(
        target_url,
        findings,
        scan_mode="browser",
        profile="launch-gate",
        packs=["leak", "appsec", "access-control", "baas"],
    )
