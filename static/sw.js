// static/sw.js
self.addEventListener('install', (e) => {
  console.log('Service Worker installé');
  self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  // Optionnel : gestion cache ici si tu veux
});
