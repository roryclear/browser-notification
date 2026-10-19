self.addEventListener("push", event => {
  const data = event.data?.json() || {};

  event.waitUntil(
    self.registration.showNotification(data.title || "Clearcam", {
      body: data.body || "Test notification"
    })
  );
});