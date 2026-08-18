// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
// Resurgamus Horizon Service Worker, required for PWA install prompt
// Minimal: caches the app shell for offline-capable detection

// Cache name = the bumpable signal that triggers a SW upgrade.
// Increment whenever JS / CSS / SHELL changes, the activate handler
// purges every cache whose name doesn't match `CACHE`, so an old
// `rhorizon-v2` left on a mobile device gets cleaned automatically
// the moment the user loads the page after a deploy.
//
// Convention : bump on every release that touches frontend/.
const CACHE = 'rhorizon-v32';
const SHELL = [
  '/',
  '/index.html',
  '/css/style.css?v=17',
  '/js/pixelarray.js',
  '/js/blackhole.js',
  '/js/qr.js',
  '/js/icons.js',
  '/js/api.js',
  '/js/views/horizon.js',
  '/js/views/dynamic.js',
  '/js/views/pki.js',
  '/js/views/eclipse.js',
  '/js/views/quasar.js',
  '/js/views/jets.js',
  '/js/views/cluster.js',
  '/js/views/nebula.js',     // Namespaces view (added 2026-05-07)
  '/js/views/accretion.js',
  '/js/views/pulsar.js',
  '/js/views/core.js',
  '/js/app.js?v=1',
  '/manifest.json',
  '/favicon.ico',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  // API calls: network only (never cache secrets)
  if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
    return;
  }
  // App shell: cache first, fallback network
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request))
  );
});
