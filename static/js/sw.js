/* Barangay Care — Web Push service worker (tracking-number based) */

self.addEventListener('install', function (event) {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(clients.claim());
});

self.addEventListener('push', function (event) {
  var data = { title: 'Barangay Care', body: '', url: '/track' };
  try {
    if (event.data) {
      data = Object.assign(data, event.data.json());
    }
  } catch (e) {
    try {
      data.body = event.data ? event.data.text() : '';
    } catch (e2) {}
  }
  event.waitUntil(
    self.registration.showNotification(data.title || 'Barangay Care', {
      body: data.body || '',
      icon: '/static/favicon.svg',
      badge: '/static/favicon.svg',
      data: { url: data.url || '/track' },
      tag: data.tracking || 'barangay-care',
      renotify: true,
    })
  );
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || '/track';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        if (list[i].url.indexOf(self.location.origin) === 0 && 'focus' in list[i]) {
          list[i].navigate(url);
          return list[i].focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});

function urlBase64ToUint8Array(base64String) {
  var padding = '='.repeat((4 - base64String.length % 4) % 4);
  var base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  var rawData = self.atob(base64);
  var outputArray = new Uint8Array(rawData.length);
  for (var i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

/* Browsers rotate/expire the push subscription in the background, with the
   page and service worker both closed. Without this handler, notifications
   would silently stop weeks later even though everything looked configured. */
self.addEventListener('pushsubscriptionchange', function (event) {
  var oldEndpoint = (event.oldSubscription && event.oldSubscription.endpoint) || '';
  event.waitUntil(
    fetch('/api/push/vapid-public-key')
      .then(function (r) { return r.json(); })
      .then(function (keyRes) {
        if (!keyRes.publicKey) throw new Error('no public key');
        return self.registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(keyRes.publicKey),
        });
      })
      .then(function (newSub) {
        return fetch('/api/push/resubscribe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ old_endpoint: oldEndpoint, subscription: newSub.toJSON() }),
        });
      })
      .catch(function (e) {
        // Best effort — nothing to show the user here, service worker has no UI.
      })
  );
});