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
})();
