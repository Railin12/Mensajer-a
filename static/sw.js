self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// Push real (funciona con la app cerrada)
self.addEventListener('push', (event) => {
  let data = { title: 'Nuevo mensaje', body: 'Tienes un mensaje nuevo' };
  try {
    if (event.data) {
      const p = event.data.json();
      if (p.title) data.title = p.title;
      if (p.body)  data.body  = p.body;
    }
  } catch (e) {}

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/static/icon.svg',
      badge: '/static/icon.svg',
      tag: 'nuevo-mensaje',
      renotify: true,
      requireInteraction: false,
    })
  );
});

// Clic en la notificacion -> abrir/focus la app
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if ('focus' in c) return c.focus();
      }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
