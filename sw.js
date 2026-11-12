const CACHE='nexabox-local-only-v39';
const ASSETS=['./','./index.html','./assets/nexabox-logo.png','./assets/nexabox-header-logo.png','./assets/nexabox-app-icon.png','./manifest.webmanifest','./assets/icon.svg','./assets/icon-white.svg'];
self.addEventListener('install',event=>event.waitUntil((async()=>{const cache=await caches.open(CACHE);await cache.addAll(ASSETS);await self.skipWaiting()})()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{for(const key of await caches.keys())if(key!==CACHE)await caches.delete(key);await self.clients.claim()})()));
self.addEventListener('fetch',event=>{
 const request=event.request;
 if(request.method!=='GET')return;
 const url=new URL(request.url);
 if(url.origin!==self.location.origin)return;
 event.respondWith((async()=>{
  const cached=await caches.match(request);
  if(cached)return cached;
  try{const response=await fetch(request);if(response.ok&&url.origin===self.location.origin){const cache=await caches.open(CACHE);cache.put(request,response.clone())}return response}
  catch(error){if(request.mode==='navigate')return (await caches.match('./index.html','./assets/nexabox-logo.png','./assets/nexabox-header-logo.png','./assets/nexabox-app-icon.png'))||Response.error();throw error}
 })());
});
