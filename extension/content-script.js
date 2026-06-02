/**
 * Content script for KeyLeak Detector.
 * Runs in the ISOLATED world. Receives intercepted data from injector.js
 * via window.postMessage and forwards to the service worker.
 * Also scans the page DOM for inline secrets.
 */

const MSG_TYPE = '__keyleak_intercepted__';

function safeSendMessage(payload) {
  try {
    if (!chrome.runtime?.id) return;
    chrome.runtime.sendMessage(payload);
  } catch (_err) {
    // Extension context invalidated (reload/update) — ignore silently.
  }
}

function sendForAnalysis(data) {
  safeSendMessage({
    action: 'analyze_content',
    data: {
      pageUrl: window.location.href,
      ...data,
    },
  });
}

function sendRemoteUrl(url, source, captureType) {
  if (!url) return;
  try {
    const resolved = new URL(url, window.location.href).toString();
    safeSendMessage({
      action: 'analyze_remote_url',
      data: {
        url: resolved,
        source,
        pageUrl: window.location.href,
        captureType,
      },
    });
  } catch (_error) {
    // Ignore malformed URLs.
  }
}

// Forward intercepted network data to service worker
window.addEventListener('message', (event) => {
  if (event.source !== window || !event.data || event.data.type !== MSG_TYPE) return;

  if (event.data.captureType === 'worker-script') {
    sendRemoteUrl(event.data.url, `Worker Script: ${event.data.url}`, 'external-script');
    return;
  }

  if (event.data.captureType === 'libraries') {
    safeSendMessage({
      action: 'analyze_libraries',
      data: {
        libraries: event.data.libraries || [],
        pageUrl: window.location.href,
      },
    });
    return;
  }

  safeSendMessage({
    action: 'analyze_intercepted',
    data: {
      source: event.data.source,
      url: event.data.url,
      status: event.data.status,
      contentType: event.data.contentType,
      body: event.data.body,
      headers: event.data.headers,
      captureType: event.data.captureType,
      pageUrl: window.location.href,
    },
  });
});

// Scan inline scripts and data attributes after page loads
function scanPageContent() {
  // Collect inline script contents
  const scripts = document.querySelectorAll('script:not([src])');
  scripts.forEach((script, idx) => {
    const text = script.textContent;
    if (text && text.trim().length > 20) {
      sendForAnalysis({
        content: text,
        source: `Inline Script #${idx + 1}`,
        captureType: 'inline-script',
      });
      scanSourceMapReferences(text, window.location.href);
    }
  });

  // Ask the service worker to fetch external browser bundles and source maps.
  const externalScripts = document.querySelectorAll('script[src]');
  externalScripts.forEach((script, idx) => {
    sendRemoteUrl(script.src, `External Script #${idx + 1}: ${script.src}`, 'external-script');
  });

  // Scan data attributes that might contain config/secrets
  const elements = document.querySelectorAll('[data-config], [data-api-key], [data-token], [data-secret], [data-auth], [data-settings]');
  elements.forEach((el) => {
    for (const attr of el.attributes) {
      const attrName = attr.name.toLowerCase();
      const looksSensitive = attrName.startsWith('data-')
        && /(config|key|token|secret|auth|credential|settings)/.test(attrName);
      if (looksSensitive && attr.value.length > 20) {
        sendForAnalysis({
          content: attr.value,
          source: `HTML data attribute: ${attr.name}`,
          captureType: 'data-attribute',
        });
      }
    }
  });

  // Scan meta tags
  const metas = document.querySelectorAll('meta[content]');
  metas.forEach((meta) => {
    const content = meta.getAttribute('content');
    if (content && content.length > 20) {
      sendForAnalysis({
        content,
        source: `Meta tag (${meta.getAttribute('name') || meta.getAttribute('property') || 'unknown'})`,
        captureType: 'meta',
      });
    }
  });

  scanBrowserStorage();
}

function scanSourceMapReferences(content, baseUrl) {
  const re = /sourceMappingURL=([^\s'"<>]+)/g;
  let match;
  while ((match = re.exec(content)) !== null) {
    sendRemoteUrl(match[1], `Source Map: ${match[1]}`, 'source-map');
  }
}

function scanBrowserStorage() {
  for (const [storageName, storage] of [['localStorage', window.localStorage], ['sessionStorage', window.sessionStorage]]) {
    try {
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        const value = storage.getItem(key);
        if (!value || value.length < 20) continue;
        if (!/(key|token|secret|auth|credential|session|config|jwt)/i.test(`${key} ${value}`)) continue;
        sendForAnalysis({
          content: `${key}=${value}`,
          source: `Browser Storage (${storageName}:${key})`,
          captureType: 'storage',
        });
      }
    } catch (_error) {
      // Some sites disable storage access for injected contexts.
    }
  }
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
        sendForAnalysis({
          content: node.textContent,
          source: 'Dynamic Inline Script',
          captureType: 'inline-script',
        });
        scanSourceMapReferences(node.textContent, window.location.href);
      }
      if (node.nodeName === 'SCRIPT' && node.src) {
        sendRemoteUrl(node.src, `Dynamic External Script: ${node.src}`, 'external-script');
      }
    }
  }
});

observer.observe(document.documentElement, { childList: true, subtree: true });
