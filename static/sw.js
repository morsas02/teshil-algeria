const CACHE_NAME = 'ta9eef-pwa-v1';
const STATIC_CACHE = 'ta9eef-static-v1';

const CORE_ASSETS = [
  '/',
  '/static/manifest.webmanifest',
  '/static/img/icon-192.png',
  '/static/img/icon-512.png',
  '/static/css/bootstrap-icons.min.css',
  '/static/fonts/bootstrap-icons.woff2'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CORE_ASSETS.length ? CACHE_NAME : STATIC_CACHE)
      .then((cache) => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME && k !== STATIC_CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) return cached;
        return fetch(req).then((res) => {
          const copy = res.clone();
          caches.open(STATIC_CACHE).then((cache) => cache.put(req, copy));
          return res;
        });
      })
    );
    return;
  }

  if (url.pathname === '/' || url.pathname.startsWith('/job/')) {
    event.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
        return res;
      }).catch(() => caches.match(req).then((cached) => cached || caches.match('/')))
    );
    return;
  }

  event.respondWith(
    fetch(req).catch(() => caches.match(req).then((cached) => cached || caches.match('/')))
  );
});
