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

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .extension_bundle import extension_pattern_payload
from .models import Evidence, Finding, ScanReport
from .reporting import build_report


SCAN_BUDGET_DEFAULT_SECONDS = 30
DEFAULT_VIEWPORT = {"width": 1280, "height": 1024}


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


def run_browser_scan(
    url: str,
    *,
    auth_state_path: Optional[str] = None,
    scan_budget_seconds: int = SCAN_BUDGET_DEFAULT_SECONDS,
    headless: bool = True,
    baas_validate: bool = True,
    baas_prober: Optional[Any] = None,
) -> ScanReport:
    """Drive Playwright Chromium, inject the analyzer, return a ScanReport.

    Raises ``ImportError`` if Playwright is not installed.
    """

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "keyleak browser-scan requires Playwright. "
            "Install with `pip install playwright && python -m playwright install chromium`."
        ) from exc

    init_script = _build_init_script()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context_kwargs: Dict[str, Any] = {"viewport": DEFAULT_VIEWPORT}
        if auth_state_path:
            context_kwargs["storage_state"] = auth_state_path
        context = browser.new_context(**context_kwargs)
        context.add_init_script(init_script)

        page = context.new_page()
        page.set_default_timeout(scan_budget_seconds * 1000)
        page.goto(url, wait_until="networkidle")
        raw = page.evaluate("() => window.__keyleak_run ? window.__keyleak_run() : []")

        baas_extraction = None
        if baas_validate:
            try:
                baas_extraction = page.evaluate(
                    "() => window.__keyleak_baas_extract ? window.__keyleak_baas_extract() : null"
                )
            except Exception:
                pass

        browser.close()

    findings = [_to_finding(entry, url) for entry in raw or []]
    baas_findings = _run_baas_validation(raw, baas_extraction, baas_validate, baas_prober)
    findings.extend(baas_findings)

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
) -> List[Finding]:
    if not baas_validate:
        return []

    from .baas_validator import extract_baas_config, validate_baas_config

    config = extract_baas_config(raw_findings, baas_extraction)
    if config is None:
        return []

    validation = validate_baas_config(config, prober=baas_prober, js_extraction=baas_extraction)
    return validation.findings


def _to_finding(entry: Dict[str, Any], target: str) -> Finding:
    source = entry.get("source") or target
    value = str(entry.get("value") or "")
    evidence = Evidence(
        source=source,
        snippet=value[:240],
        redacted_value=value[:120],
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
    findings = [_to_finding(entry, target_url) for entry in raw_findings or []]
    baas_findings = _run_baas_validation(raw_findings, baas_extraction, baas_validate, baas_prober)
    findings.extend(baas_findings)
    return build_report(
        target_url,
        findings,
        scan_mode="browser",
        profile="launch-gate",
        packs=["leak", "appsec", "access-control", "baas"],
    )
