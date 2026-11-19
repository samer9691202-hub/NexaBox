/* Vaulty — Service Worker: يتيح العمل بدون إنترنت */
const CACHE = 'vaulty-1.0.14-ios3';
const ASSETS = ['./', './index.html', './style.css', './app.js', './manifest.webmanifest',
  './icons/icon-192.png', './icons/icon-512.png', './icons/maskable-512.png', './icons/apple-touch-icon.png', './icons/icon.svg',
  './fonts/NotoSansArabic-Regular.ttf', './fonts/NotoSansArabic-Medium.ttf', './fonts/NotoSansArabic-Bold.ttf'];

// Safari يرفض أي استجابة من الـ Service Worker فيها إعادة توجيه (redirect)؛ نُنشئ نسخة نظيفة منها.
async function clean(res) {
  if (!res.redirected) return res;
  const body = await res.blob();
  return new Response(body, { status: res.status, statusText: res.statusText, headers: res.headers });
}

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(async c => {
      for (const a of ASSETS) {
        const r = await fetch(a, { cache: 'reload' });
        if (!r.ok) throw new Error('asset-failed: ' + a);
        await c.put(a, await clean(r));
      }
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // ملفات التطبيق: من الذاكرة أولاً ثم الشبكة. تحديث الكاش لا يمس بيانات الخزنة في localStorage.
  if (url.origin === location.origin) {
    e.respondWith(
      caches.match(req, { ignoreSearch: true }).then(hit => hit ? clean(hit) : fetch(req).then(async res => {
        const out = await clean(res);
        if (out.ok) { const copy = out.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
        return out;
      }).catch(() => caches.match('./index.html').then(r => r ? clean(r) : Response.error())))
    );
    return;
  }
});
