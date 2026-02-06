const PREFIX = '/tur';
const MAX_RETRIES = 3;
const RETRY_DELAY_BASE = 3000;
const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;
const TIMEOUT_MS = 30000;
const CACHE_TTL_SECONDS = 900;
const HEAD_TIMEOUT_MS = 3000;
const CF_ALLOWED_COUNTRIES = ['CN'];

// fetch 带重试
async function fetchWithRetry(url, options = {}, attempt = 1) {
  const method = (options && options.method) || 'GET';
  const timeoutMsDefault = method === 'HEAD' ? HEAD_TIMEOUT_MS : TIMEOUT_MS;
  const timeoutMs = options && typeof options.timeoutMs === 'number' ? options.timeoutMs : timeoutMsDefault;
  const controller = timeoutMs > 0 ? new AbortController() : null;
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort("timeout"), timeoutMs) : null;
  try {
    if (method === 'HEAD') {
      return await fetch(url, { ...options, signal: controller ? controller.signal : undefined });
    } else {
      const response = await fetch(url, { ...options, signal: controller ? controller.signal : undefined });
      if (!response.ok && attempt < MAX_RETRIES) {
        await new Promise(r => setTimeout(r, RETRY_DELAY_BASE * attempt));
        return fetchWithRetry(url, options, attempt + 1);
      }
      return response;
    }
  } catch (err) {
    if (method !== 'HEAD' && attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, RETRY_DELAY_BASE * attempt));
      return fetchWithRetry(url, options, attempt + 1);
    }
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// 获取 GitHub URL（primary/fallback）
async function getPoolUrl(packageDebName) {
  const packageDebNameModified = packageDebName.replaceAll(/[^a-zA-Z0-9-_+%]+/g, ".");
  const safeName = encodeURI(packageDebNameModified);
  const packageName = packageDebNameModified.split("_").at(0);

  const primaryUrl = `https://github.com/termux-user-repository/dists/releases/download/${packageName}/${safeName}`;
  const fallbackUrl = `https://github.com/termux-user-repository/dists/releases/download/0.1/${safeName}`;

  let usePrimary = false;
  try {
    const headResp = await fetchWithRetry(primaryUrl, { method: "HEAD" });
    if (headResp.ok) usePrimary = true;
  } catch (e) {}

  return usePrimary ? primaryUrl : fallbackUrl;
}

// 流式 fetch + Worker 缓存 + 尽量 CDN 缓存
async function fetchAndStream(url, request, context) {
  const cache = caches.default;

  // 先尝试 Worker 缓存
  const cached = await cache.match(request);
  if (cached) return cached;

  // fetch GitHub
  const forward = new Headers();
  ['range','if-range','if-none-match','if-modified-since','accept','user-agent'].forEach(k => {
    const v = request.headers.get(k);
    if (v) forward.set(k, v);
  });
  const isGetReq = request.method === 'GET';
  const isDebReq = url.endsWith(".deb");
  const hasRangeReq = !!request.headers.get('range');
  const response = await fetchWithRetry(url, {
    cf: (!hasRangeReq && isGetReq && isDebReq) ? { cacheEverything: true, cacheTtl: ONE_YEAR_SECONDS } : undefined,
    headers: forward,
    method: request.method,
    timeoutMs: isGetReq && isDebReq ? 0 : TIMEOUT_MS
  });
  if (!response.body) return response;

  function sanitizeHeaders(src) {
    const h = new Headers(src);
    const hopByHop = [
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade'
    ];
    hopByHop.forEach(k => h.delete(k));
    return h;
  }
  function withSecurity(src) {
    const h = new Headers(src);
    h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    h.set('X-Frame-Options', 'DENY');
    h.set('X-XSS-Protection', '1; mode=block');
    h.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    h.set('Referrer-Policy', 'no-referrer');
    return h;
  }

  const isGet = isGetReq;
  const isDeb = isDebReq;
  const hasRange = hasRangeReq;
  const isPartial = response.status === 206;
  const shouldCache = !hasRange && !isPartial && isDeb && isGet;

  if (isGet && isDeb && shouldCache) {
    const [clientStream, cacheStream] = response.body.tee();

    // 返回给客户端
    const clientHeaders = withSecurity(sanitizeHeaders(response.headers));
    clientHeaders.set("Cache-Control", `public, max-age=${ONE_YEAR_SECONDS}`);
    const clientResponse = new Response(clientStream, {
      status: response.status,
      statusText: response.statusText,
      headers: clientHeaders
    });

    const cacheHeaders = withSecurity(sanitizeHeaders(response.headers));
    cacheHeaders.set("Cache-Control", `public, max-age=${ONE_YEAR_SECONDS}`);
    const cacheResponse = new Response(cacheStream, {
      status: response.status,
      statusText: response.statusText,
      headers: cacheHeaders
    });
    context.waitUntil((async () => {
      try {
        await cache.put(request, cacheResponse);
      } catch (_) {}
    })());

    return clientResponse;
  }

  return response;
}


function pageSanitizeHeaders(src) {
  const h = new Headers(src);
  ['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'].forEach(k => h.delete(k));
  return h;
}
function pageSecurity(src) {
  const h = new Headers(src);
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  h.set('X-Frame-Options', 'DENY');
  h.set('X-XSS-Protection', '1; mode=block');
  h.set('Content-Security-Policy', "default-src 'self' https://cmsz001.github.io/tur-mirror/; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self' https://cmsz001.github.io/tur-mirror/ data:; frame-ancestors 'none'; base-uri 'none'");
  h.set('Referrer-Policy', 'no-referrer');
  return h;
}

async function fetchMirrorPage(url, request, context) {
  const cache = caches.default;
  const cached = await cache.match(request);
  if (cached) return cached;

  const forward = new Headers();
  ['accept','user-agent'].forEach(k => {
    const v = request.headers.get(k);
    if (v) forward.set(k, v);
  });
  const response = await fetchWithRetry(url, {
    cf: { cacheEverything: true, cacheTtl: CACHE_TTL_SECONDS },
    headers: forward,
    method: request.method,
    timeoutMs: 0
  });
  if (!response.body) {
    const headers = pageSecurity(pageSanitizeHeaders(response.headers));
    headers.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
  const [clientStream, cacheStream] = response.body.tee();
  const clientHeaders = pageSecurity(pageSanitizeHeaders(response.headers));
  clientHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`);
  const clientResponse = new Response(clientStream, { status: response.status, statusText: response.statusText, headers: clientHeaders });
  const cacheHeaders = pageSecurity(pageSanitizeHeaders(response.headers));
  cacheHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`);
  const cacheResponse = new Response(cacheStream, { status: response.status, statusText: response.statusText, headers: cacheHeaders });
  context.waitUntil((async () => { try { await cache.put(request, cacheResponse); } catch (_) {} })());
  return clientResponse;
}

export async function onRequestGet(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.headers.get('checkmode')) {
    return new Response("ITDOG filter", { status: 500 });
  }
  if (request.method !== 'GET') {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (path.length > 2048) {
    return new Response("URI Too Long", { status: 414 });
  }
  if (path.includes("..")) {
    return new Response("Bad Request", { status: 400 });
  }

  if (path.startsWith(PREFIX + '/pool/') && !path.endsWith('/')) {
    const pathArray = path.split('/');
    const packageDebName = pathArray.at(-1);
    if (!packageDebName || !packageDebName.endsWith('.deb')) {
      return new Response("Not Found", { status: 404 });
    }
    try {
      const country = (request.cf && request.cf.country) || '';
      const isCFAllowed = CF_ALLOWED_COUNTRIES.includes(country);
      const mainUrl = await getPoolUrl(packageDebName);
      if (!isCFAllowed) {
        return new Response(null, { status: 302, headers: { Location: mainUrl } });
      }
      return fetchAndStream(mainUrl, request, context);
    } catch (err) {
      return new Response("All pool upstreams failed: " + err, { status: 502 });
    }
  }
  if (path.startsWith(PREFIX + '/pool/') && path.endsWith('/')) {
    const upstreamPath = path.replace(new RegExp(`^${PREFIX}`), "");
    const mirrorUrl = `https://cmsz001.github.io/tur-mirror${upstreamPath}`;
    try {
      return await fetchMirrorPage(mirrorUrl, request, context);
    } catch (err) {
      return new Response("pool directory upstream failed: " + err, { status: 502 });
    }
  }
  return new Response("Not Found", { status: 404 });
}

export async function onRequestHead(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.headers.get('checkmode')) {
    return new Response("ITDOG filter", { status: 500 });
  }
  if (request.method !== 'HEAD') {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (path.length > 2048) {
    return new Response("URI Too Long", { status: 414 });
  }
  if (path.includes("..")) {
    return new Response("Bad Request", { status: 400 });
  }

  if (path.startsWith(PREFIX + '/pool/') && !path.endsWith('/')) {
    const pathArray = path.split('/');
    const packageDebName = pathArray.at(-1);
    if (!packageDebName || !packageDebName.endsWith('.deb')) {
      return new Response("Not Found", { status: 404 });
    }
    try {
      const country = (request.cf && request.cf.country) || '';
      const isCFAllowed = CF_ALLOWED_COUNTRIES.includes(country);
      const mainUrl = await getPoolUrl(packageDebName);
      if (!isCFAllowed) {
        return new Response(null, { status: 302, headers: { Location: mainUrl } });
      } else {
        const response = await fetchWithRetry(mainUrl, { method: "HEAD" });
        return new Response(null, {
          status: response.status,
          statusText: response.statusText,
          headers: pageSecurity(pageSanitizeHeaders(response.headers))
        });
      }
    } catch (err) {
      return new Response("All pool upstreams failed: " + err, { status: 502 });
    }
  }
  if (path.startsWith(PREFIX + '/pool/') && path.endsWith('/')) {
    const upstreamPath = path.replace(new RegExp(`^${PREFIX}`), "");
    const mirrorUrl = `https://cmsz001.github.io/tur-mirror${upstreamPath}`;
    try {
      const response = await fetchWithRetry(mirrorUrl, { method: "HEAD" });
      return new Response(null, {
        status: response.status,
        statusText: response.statusText,
        headers: pageSecurity(pageSanitizeHeaders(response.headers))
      });
    } catch (err) {
      return new Response("pool directory upstream failed: " + err, { status: 502 });
    }
  }
  return new Response("Not Found", { status: 404 });
}
