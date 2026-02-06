const PREFIX = '/tur';
const MAX_RETRIES = 3;
const RETRY_DELAY_BASE = 1000;
const TIMEOUT_MS = 30000;
const CACHE_TTL_SECONDS = 900;
const HEAD_TIMEOUT_MS = 3000;

/**
 * 带重试的 fetch（HEAD 请求不重试）
 */
async function fetchWithRetry(url, options = {}, attempt = 1) {
  const method = (options && options.method) || 'GET';
  if (method === 'HEAD') return fetch(url, options);

  const timeoutMs = options && typeof options.timeoutMs === 'number' ? options.timeoutMs : TIMEOUT_MS;
  const controller = timeoutMs > 0 ? new AbortController() : null;
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort("timeout"), timeoutMs) : null;

  try {
    const response = await fetch(url, { ...options, signal: controller ? controller.signal : undefined });

    if (!response.ok && attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, RETRY_DELAY_BASE * attempt));
      return fetchWithRetry(url, options, attempt + 1);
    }

    return response;
  } catch (err) {
    if (attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, RETRY_DELAY_BASE * attempt));
      return fetchWithRetry(url, options, attempt + 1);
    }
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * 判断路径是否是文件
 * 简单规则：路径不以 / 结尾，或者包含点（Release、Packages、*.deb 等）
 */
function isFilePath(path) {
  const lastSegment = path.split('/').pop();
  return !!lastSegment && (!path.endsWith('/') || lastSegment.includes('.'));
}

function sanitizeHeaders(src) {
  const h = new Headers(src);
  ['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'].forEach(k => h.delete(k));
  return h;
}
function withSecurity(src, allowMirror) {
  const h = new Headers(src);
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  h.set('X-Frame-Options', 'DENY');
  h.set('X-XSS-Protection', '1; mode=block');
  h.set('Content-Security-Policy', allowMirror
    ? "default-src 'self' https://tur-mirror.pages.dev; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self' https://tur-mirror.pages.dev data:; frame-ancestors 'none'; base-uri 'none'"
    : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  );
  h.set('Referrer-Policy', 'no-referrer');
  return h;
}

function buildUpstreamUrl(upstreamPath) {
  if (isFilePath(upstreamPath)) {
    return `https://raw.githubusercontent.com/termux-user-repository/dists/refs/heads/master${upstreamPath}`;
  }
  return `https://tur-mirror.pages.dev${upstreamPath}`;
}

async function fetchAndStream(upstreamUrl, request, context) {
  const cache = caches.default;

  const cached = await cache.match(request);
  if (cached) return cached;

  const forward = new Headers();
  ['range','if-range','if-none-match','if-modified-since','accept','user-agent'].forEach(k => {
    const v = request.headers.get(k);
    if (v) forward.set(k, v);
  });

  const isGet = request.method === 'GET';
  const isFile = isFilePath(new URL(upstreamUrl).pathname);
  const hasRange = !!request.headers.get('range');
  const allowMirror = !isFile;

  const response = await fetchWithRetry(upstreamUrl, {
    cf: (!hasRange && isGet && !isFile) ? { cacheEverything: true, cacheTtl: CACHE_TTL_SECONDS } : undefined,
    headers: forward,
    method: request.method,
    timeoutMs: isGet && !isFile ? 0 : TIMEOUT_MS
  });

  if (!response.body) {
    const headers = withSecurity(sanitizeHeaders(response.headers), allowMirror);
    headers.set('Cache-Control', (isGet && !isFile && !hasRange) ? `public, max-age=${CACHE_TTL_SECONDS}` : 'no-store, no-cache, must-revalidate');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }

  const isPartial = response.status === 206;
  const shouldCache = isGet && !isFile && !hasRange && !isPartial;

  if (shouldCache) {
    const [clientStream, cacheStream] = response.body.tee();

    const clientHeaders = withSecurity(sanitizeHeaders(response.headers), allowMirror);
    clientHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`);
    const clientResponse = new Response(clientStream, {
      status: response.status,
      statusText: response.statusText,
      headers: clientHeaders
    });

    const cacheHeaders = withSecurity(sanitizeHeaders(response.headers), allowMirror);
    cacheHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`);
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

  const headers = withSecurity(sanitizeHeaders(response.headers), allowMirror);
  headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

/**
 * Pages Function
 */
export async function onRequestGet(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.headers.get('checkmode')) return new Response("ITDOG filter", { status: 500 });
  if (request.method !== 'GET') return new Response("Method Not Allowed", { status: 405 });
  if (path.length > 2048) return new Response("URI Too Long", { status: 414 });
  if (path.includes("..")) return new Response("Bad Request", { status: 400 });

  const upstreamPath = path.replace(new RegExp(`^${PREFIX}`), "");
  const upstreamUrl = buildUpstreamUrl(upstreamPath);
  try {
    return await fetchAndStream(upstreamUrl, request, context);
  } catch (err) {
    return new Response("Upstream fetch error: " + err, { status: 502 });
  }
}

export async function onRequestHead(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.headers.get('checkmode')) return new Response("ITDOG filter", { status: 500 });
  if (request.method !== 'HEAD') return new Response("Method Not Allowed", { status: 405 });
  if (path.length > 2048) return new Response("URI Too Long", { status: 414 });
  if (path.includes("..")) return new Response("Bad Request", { status: 400 });

  const upstreamPath = path.replace(new RegExp(`^${PREFIX}`), "");
  const upstreamUrl = buildUpstreamUrl(upstreamPath);
  try {
    const response = await fetchWithRetry(upstreamUrl, { method: 'HEAD', timeoutMs: HEAD_TIMEOUT_MS });
    return new Response(null, {
      status: response.status,
      statusText: response.statusText,
      headers: withSecurity(sanitizeHeaders(response.headers), !isFilePath(new URL(upstreamUrl).pathname))
    });
  } catch (err) {
    return new Response("Upstream HEAD error: " + err, { status: 502 });
  }
}
