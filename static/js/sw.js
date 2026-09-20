/* Barangay Care — Web Push service worker (tracking-number based) */
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
