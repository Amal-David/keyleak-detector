/* Build replaces these tokens with a content digest and an exact asset list. */
const VERSION = '__KEYLEAK_CACHE_VERSION__';
const ASSETS = __KEYLEAK_OFFLINE_ASSETS__;
const PREFIX = `keyleak-assets:${self.registration.scope}:`;
const CACHE = `${PREFIX}${VERSION}`;
const ROOT = new URL(self.registration.scope);
const ALLOWED = new Set(ASSETS.map(path => new URL(path, ROOT).href));

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(
    [...ALLOWED].map(url => new Request(url, { credentials: 'omit', cache: 'reload' })),
  )));
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith(PREFIX) && key !== CACHE) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== ROOT.origin || url.search) return;
  const key = url.href === ROOT.href ? new URL('./index.html', ROOT).href : url.href;
  if (!ALLOWED.has(key)) return;
  // Only immutable build assets enter this cache. Scanned responses, reports,
  // arbitrary routes and the separately hosted PHP checker are never cached.
  event.respondWith(caches.open(CACHE).then(async cache => (await cache.match(key)) || fetch(event.request)));
});
