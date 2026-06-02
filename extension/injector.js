/**
 * MAIN world injector for KeyLeak Detector.
 * Monkey-patches fetch() and XMLHttpRequest to intercept response bodies.
 * Sends intercepted data back to the content script via window.postMessage.
 *
 * This runs in the page's JS context (MAIN world) at document_start.
 */

(function () {
  'use strict';

  const MSG_TYPE = '__keyleak_intercepted__';
  const MAX_BODY_SIZE = 2 * 1024 * 1024; // 2MB limit

  // Skip non-text content types
  function isTextContent(contentType) {
    if (!contentType) return true; // assume text if unknown
    const ct = contentType.toLowerCase();
    return ct.includes('text/') ||
      ct.includes('application/json') ||
      ct.includes('application/javascript') ||
      ct.includes('application/xml') ||
      ct.includes('application/x-www-form-urlencoded');
  }

  function scanMessageBody(source, url, body, contentType = 'text/plain') {
    if (typeof body !== 'string') return;
    if (!body || body.length >= MAX_BODY_SIZE) return;
    sendToContentScript({
      source,
      url,
      status: 200,
      contentType,
      body: body.slice(0, MAX_BODY_SIZE),
      headers: [],
      captureType: source,
    });
  }

  function sendToContentScript(data) {
    try {
      window.postMessage({ type: MSG_TYPE, ...data }, '*');
    } catch (e) {
      // Silently fail — don't break the page
    }
  }

  // --- Patch fetch() ---
  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await originalFetch.apply(this, args);

    try {
      const url = (typeof args[0] === 'string') ? args[0] : args[0]?.url || '';
      const contentType = response.headers.get('content-type') || '';

      if (isTextContent(contentType) && response.status < 400) {
        // Clone to avoid consuming the body
        const clone = response.clone();
        clone.text().then(body => {
          if (body && body.length > 0 && body.length < MAX_BODY_SIZE) {
            sendToContentScript({
              source: 'fetch',
              url,
              status: response.status,
              contentType,
              body: body.slice(0, MAX_BODY_SIZE),
              headers: [...response.headers.entries()].map(([n, v]) => ({ name: n, value: v })),
            });
          }
        }).catch(() => {});
      }
    } catch (e) {
      // Never break the page
    }

    return response;
  };

  // --- Patch XMLHttpRequest ---
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__keyleak_url = url;
    this.__keyleak_method = method;
    return originalXHROpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (...args) {
    this.addEventListener('load', function () {
      try {
        const contentType = this.getResponseHeader('content-type') || '';
        if (isTextContent(contentType) && this.status < 400) {
          const body = this.responseText;
          if (body && body.length > 0 && body.length < MAX_BODY_SIZE) {
            sendToContentScript({
              source: 'xhr',
              url: this.__keyleak_url || '',
              status: this.status,
              contentType,
              body: body.slice(0, MAX_BODY_SIZE),
              headers: (this.getAllResponseHeaders() || '').split('\r\n')
                .filter(Boolean)
                .map(line => {
                  const idx = line.indexOf(':');
                  return { name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
                }),
            });
          }
        }
      } catch (e) {
        // Never break the page
      }
    });
    return originalXHRSend.apply(this, args);
  };

  // --- Patch WebSocket messages ---
  const OriginalWebSocket = window.WebSocket;
  if (OriginalWebSocket) {
    window.WebSocket = function (url, protocols) {
      const socket = protocols === undefined ? new OriginalWebSocket(url) : new OriginalWebSocket(url, protocols);
      socket.addEventListener('message', function (event) {
        try {
          scanMessageBody('websocket', String(url || ''), event.data, 'text/plain');
        } catch (e) {
          // Never break the page.
        }
      });
      return socket;
    };
    window.WebSocket.prototype = OriginalWebSocket.prototype;
    Object.defineProperty(window.WebSocket, 'OPEN', { value: OriginalWebSocket.OPEN });
    Object.defineProperty(window.WebSocket, 'CONNECTING', { value: OriginalWebSocket.CONNECTING });
    Object.defineProperty(window.WebSocket, 'CLOSING', { value: OriginalWebSocket.CLOSING });
    Object.defineProperty(window.WebSocket, 'CLOSED', { value: OriginalWebSocket.CLOSED });
  }

  // --- Patch EventSource/SSE messages ---
  const OriginalEventSource = window.EventSource;
  if (OriginalEventSource) {
    window.EventSource = function (url, config) {
      const stream = new OriginalEventSource(url, config);
      stream.addEventListener('message', function (event) {
        try {
          scanMessageBody('eventstream', String(url || ''), event.data, 'text/event-stream');
        } catch (e) {
          // Never break the page.
        }
      });
      return stream;
    };
    window.EventSource.prototype = OriginalEventSource.prototype;
    // Preserve the static readyState constants so page code comparing against
    // EventSource.OPEN/CONNECTING/CLOSED keeps working (never break the page).
    Object.defineProperty(window.EventSource, 'CONNECTING', { value: OriginalEventSource.CONNECTING });
    Object.defineProperty(window.EventSource, 'OPEN', { value: OriginalEventSource.OPEN });
    Object.defineProperty(window.EventSource, 'CLOSED', { value: OriginalEventSource.CLOSED });
  }

  // --- Track worker script URLs so the extension can fetch/scan worker bundles ---
  const OriginalWorker = window.Worker;
  if (OriginalWorker) {
    window.Worker = function (scriptURL, options) {
      try {
        sendToContentScript({
          source: 'worker-script',
          url: typeof scriptURL === 'string' ? scriptURL : String(scriptURL || ''),
          status: 0,
          contentType: 'application/javascript',
          body: '',
          headers: [],
          captureType: 'worker-script',
        });
      } catch (e) {
        // Never break the page.
      }
      return new OriginalWorker(scriptURL, options);
    };
    window.Worker.prototype = OriginalWorker.prototype;
  }

  // --- Frontend library version scan (retire.js-style) ---
  // Reads runtime version globals first, then falls back to parsing the version
  // out of <script src> filenames for libraries not exposed as globals. Runs in
  // the MAIN world because globals like window.jQuery are not visible to the
  // isolated content script. The version -> CVE matching happens in the service
  // worker (lib/library-cves.js); here we only collect raw (name, version).
  function scanLibraries() {
    var libs = [];
    try {
      if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
        libs.push({ name: 'jquery', version: window.jQuery.fn.jquery, source: 'global' });
      } else if (window.$ && window.$.fn && window.$.fn.jquery) {
        libs.push({ name: 'jquery', version: window.$.fn.jquery, source: 'global' });
      }
      if (window.bootstrap && (window.bootstrap.Tooltip || window.bootstrap.Alert)) {
        libs.push({ name: 'bootstrap', version: (window.bootstrap.Tooltip || window.bootstrap.Alert).VERSION, source: 'global' });
      } else if (window.jQuery && window.jQuery.fn && window.jQuery.fn.tooltip && window.jQuery.fn.tooltip.Constructor) {
        // Bootstrap 4 registers as a jQuery plugin exposing Constructor.VERSION.
        libs.push({ name: 'bootstrap', version: window.jQuery.fn.tooltip.Constructor.VERSION, source: 'global' });
      }
      if (window.React && window.React.version) {
        libs.push({ name: 'react', version: window.React.version, source: 'global' });
      }
      if (window.Vue && window.Vue.version) {
        libs.push({ name: 'vue', version: window.Vue.version, source: 'global' });
      }
      if (window.angular && typeof window.angular.version === 'object' && window.angular.version.full) {
        libs.push({ name: 'angular', version: window.angular.version.full, source: 'global' });
      }
      var SRC_RE = [
        ['jquery', /jquery[-.]?(\d+\.\d+\.\d+)/i],
        ['bootstrap', /bootstrap[-.]?(\d+\.\d+\.\d+)/i],
        ['angular', /angular[-.]?(\d+\.\d+\.\d+)/i],
      ];
      var srcs = document.querySelectorAll('script[src]');
      for (var i = 0; i < srcs.length; i++) {
        var src = srcs[i].src || '';
        for (var j = 0; j < SRC_RE.length; j++) {
          var m = SRC_RE[j][1].exec(src);
          if (m) libs.push({ name: SRC_RE[j][0], version: m[1], source: 'script-url', url: src });
        }
      }
    } catch (_err) {
      // Swallow — best-effort enumeration, never break the page.
    }

    if (libs.length > 0) {
      try {
        window.postMessage({ type: MSG_TYPE, captureType: 'libraries', libraries: libs }, '*');
      } catch (_e) {
        // Silently fail.
      }
    }
  }

  // Libraries register after document_start, so scan on load and once more a few
  // seconds later to catch lazily-loaded bundles. Duplicate findings dedupe by id.
  if (document.readyState === 'complete') {
    scanLibraries();
  } else {
    window.addEventListener('load', scanLibraries);
  }
  setTimeout(scanLibraries, 3000);
})();
