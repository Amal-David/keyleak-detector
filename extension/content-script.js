/**
 * Content script for KeyLeak Detector.
 * Runs in the ISOLATED world. Receives intercepted data from injector.js
 * via window.postMessage and forwards to the service worker.
 * Also scans the page DOM for inline secrets.
 */

const MSG_TYPE = '__keyleak_intercepted__';

// Forward intercepted network data to service worker
window.addEventListener('message', (event) => {
  if (event.source !== window || !event.data || event.data.type !== MSG_TYPE) return;

  chrome.runtime.sendMessage({
    action: 'analyze_intercepted',
    data: {
      source: event.data.source,
      url: event.data.url,
      status: event.data.status,
      contentType: event.data.contentType,
      body: event.data.body,
      headers: event.data.headers,
      pageUrl: window.location.href,
    },
  });
});

// Scan inline scripts and data attributes after page loads
function scanPageContent() {
  const findings = [];

  // Collect inline script contents
  const scripts = document.querySelectorAll('script:not([src])');
  scripts.forEach((script, idx) => {
    const text = script.textContent;
    if (text && text.trim().length > 20) {
      chrome.runtime.sendMessage({
        action: 'analyze_content',
        data: {
          content: text,
          source: `Inline Script #${idx + 1}`,
          pageUrl: window.location.href,
        },
      });
    }
  });

  // Scan data attributes that might contain config/secrets
  const elements = document.querySelectorAll('[data-config], [data-api-key], [data-token], [data-secret]');
  elements.forEach((el) => {
    for (const attr of el.attributes) {
      if (attr.name.startsWith('data-') && attr.value.length > 20) {
        chrome.runtime.sendMessage({
          action: 'analyze_content',
          data: {
            content: attr.value,
            source: `HTML data attribute: ${attr.name}`,
            pageUrl: window.location.href,
          },
        });
      }
    }
  });

  // Scan meta tags
  const metas = document.querySelectorAll('meta[content]');
  metas.forEach((meta) => {
    const content = meta.getAttribute('content');
    if (content && content.length > 20) {
      chrome.runtime.sendMessage({
        action: 'analyze_content',
        data: {
          content,
          source: `Meta tag (${meta.getAttribute('name') || meta.getAttribute('property') || 'unknown'})`,
          pageUrl: window.location.href,
        },
      });
    }
  });
}

// Run DOM scan after page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scanPageContent);
} else {
  scanPageContent();
}

// Also observe for dynamically added scripts
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeName === 'SCRIPT' && !node.src && node.textContent?.trim().length > 20) {
        chrome.runtime.sendMessage({
          action: 'analyze_content',
          data: {
            content: node.textContent,
            source: 'Dynamic Inline Script',
            pageUrl: window.location.href,
          },
        });
      }
    }
  }
});

observer.observe(document.documentElement, { childList: true, subtree: true });
