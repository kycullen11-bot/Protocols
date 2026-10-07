/* Kyle Master Protocol — offline service worker.
   All app code (HTML/CSS/JS) lives inside index.html; this worker just keeps
   a copy of it (plus the manifest and icons) so the app opens without internet.
   Paths are relative to this file, so it works in any GitHub Pages sub-folder.
   Bump VERSION whenever index.html changes so phones pick up the new copy.

   Safety rules (5.1):
   - A new version only installs if the app page itself downloaded correctly; otherwise the
     current working copy stays in charge (a half-finished install can't replace it).
   - Old copies are deleted only after the new copy is confirmed in the cache.
   - A page load uses the network when it answers properly; an error page (404 / 5xx during a
     GitHub Pages deploy) or no answer within 4 s falls back to the saved copy. */
var VERSION = "kmp-2026-10-03-r8";
var REQUIRED = ["./index.html"];
var OPTIONAL = ["./manifest.webmanifest", "./icon-192.png", "./icon-512.png", "./apple-touch-icon.png"];

self.addEventListener("install", function (e) {
  e.waitUntil(
    caches.open(VERSION).then(function (c) {
      // cache: "reload" bypasses the HTTP cache so a fresh copy is stored
      var must = REQUIRED.map(function (u) {
        return fetch(new Request(u, { cache: "reload" })).then(function (r) {
          if (!r || !r.ok) throw new Error("install: " + u + " → " + (r ? r.status : "no response"));
          return Promise.all([c.put(u, r.clone()), c.put("./", r)]);
        });
      });
      var may = OPTIONAL.map(function (u) {
        return fetch(new Request(u, { cache: "reload" })).then(function (r) { if (r && r.ok) return c.put(u, r); }).catch(function () {});
      });
      return Promise.all(must.concat(may));
    }).then(function () { return self.skipWaiting(); })
      // a rejected promise fails the install: the previous version keeps running, and the half-filled cache is removed
      .catch(function (err) { return caches.delete(VERSION).then(function () { throw err; }); })
  );
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.open(VERSION).then(function (c) { return c.match("./index.html"); }).then(function (have) {
      if (!have) return;   // never delete the old copy unless the new one is really there
      return caches.keys().then(function (keys) {
        return Promise.all(keys.filter(function (k) {
          return k.indexOf("kmp-") === 0 && k !== VERSION;
        }).map(function (k) { return caches.delete(k); }));
      });
    }).then(function () { return self.clients.claim(); })
  );
});

function timeout(ms) { return new Promise(function (_, rej) { setTimeout(function () { rej(new Error("timeout")); }, ms); }); }
function savedPage() {
  return caches.open(VERSION).then(function (c) {
    return c.match("./index.html").then(function (m) { return m || c.match("./"); });
  }).then(function (m) {
    if (m) return m;
    // this version's cache is empty (very first load): try any older copy
    return caches.keys().then(function (keys) {
      var old = keys.filter(function (k) { return k.indexOf("kmp-") === 0; });
      return old.reduce(function (p, k) { return p.then(function (hit) { return hit || caches.open(k).then(function (c) { return c.match("./index.html"); }); }); }, Promise.resolve(null));
    });
  });
}

self.addEventListener("fetch", function (e) {
  var req = e.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;           // external videos/links: straight to network
  var scope = new URL(self.registration.scope);
  if (url.pathname.indexOf(scope.pathname) !== 0) return;    // outside this app's folder

  // Page loads: the network (revalidated, 4 s) so updates arrive; anything but a proper page → the saved copy.
  if (req.mode === "navigate") {
    e.respondWith(
      Promise.race([fetch(req.url, { cache: "no-cache", credentials: "same-origin" }), timeout(4000)]).then(function (r) {
        if (r && r.redirected) return Response.redirect(r.url, 302);   // a page can't be answered with a followed redirect
        if (r && r.ok && (r.headers.get("content-type") || "").indexOf("text/html") > -1) {
          var copy = r.clone();
          caches.open(VERSION).then(function (c) { c.put("./index.html", copy); });
          return r;
        }
        return savedPage().then(function (m) { return m || r; });
      }).catch(function () {
        return savedPage().then(function (m) { return m || new Response("Offline and no saved copy yet — open the app once while online.", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" } }); });
      })
    );
    return;
  }

  // Everything else in scope (manifest, icons): cache first, then network.
  e.respondWith(
    caches.open(VERSION).then(function (c) {
      return c.match(req, { ignoreSearch: true }).then(function (m) {
        return m || fetch(req).then(function (r) {
          if (r && r.ok && r.type === "basic") c.put(req, r.clone());
          return r;
        });
      });
    })
  );
});
