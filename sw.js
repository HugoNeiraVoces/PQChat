const CACHE_NAME = 'pqchat-v3';

self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('push', function(event) {
    if (!event.data) return;

    let data = {};
    try {
        data = event.data.json();
    } catch (e) {
        data = { title: 'PQChat', body: event.data.text() };
    }

    const title = data.title || 'PQChat';
    const options = {
        body: data.body || 'New Message',
        icon: '/pictures/icon-192.png',
        badge: '/pictures/badge-monochrome.png',
        vibrate: [200, 100, 200]
    };

    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('/')
    );
});
