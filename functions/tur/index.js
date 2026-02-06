const CACHE_TTL_SECONDS = 900
const TIMEOUT_MS = 30000

async function fetchWithRetry(url, options = {}, attempt = 1) {
  const method = (options && options.method) || 'GET'
  if (method === 'HEAD') return fetch(url, options)
  const timeoutMs = options && typeof options.timeoutMs === 'number' ? options.timeoutMs : TIMEOUT_MS
  const controller = timeoutMs > 0 ? new AbortController() : null
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort('timeout'), timeoutMs) : null
  try {
    const response = await fetch(url, { ...options, signal: controller ? controller.signal : undefined })
    return response
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function sanitizeHeaders(src) {
  const h = new Headers(src)
  ;['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'].forEach(k => h.delete(k))
  return h
}
function withSecurity(src) {
  const h = new Headers(src)
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  h.set('X-Frame-Options', 'DENY')
  h.set('X-XSS-Protection', '1; mode=block')
  h.set('Content-Security-Policy', "default-src 'self' https://tur-mirror.pages.dev; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self' https://tur-mirror.pages.dev data:; frame-ancestors 'none'; base-uri 'none'")
  h.set('Referrer-Policy', 'no-referrer')
  return h
}

async function fetchAndStream(upstreamUrl, request, context) {
  const cache = caches.default
  const cached = await cache.match(request)
  if (cached) return cached

  const forward = new Headers()
  ;['accept','user-agent'].forEach(k => {
    const v = request.headers.get(k)
    if (v) forward.set(k, v)
  })

  const response = await fetchWithRetry(upstreamUrl, {
    cf: { cacheEverything: true, cacheTtl: CACHE_TTL_SECONDS },
    headers: forward,
    method: request.method,
    timeoutMs: 0
  })

  if (!response.body) {
    const headers = withSecurity(sanitizeHeaders(response.headers))
    headers.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`)
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
  }

  const [clientStream, cacheStream] = response.body.tee()

  const clientHeaders = withSecurity(sanitizeHeaders(response.headers))
  clientHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`)
  const clientResponse = new Response(clientStream, {
    status: response.status,
    statusText: response.statusText,
    headers: clientHeaders
  })

  const cacheHeaders = withSecurity(sanitizeHeaders(response.headers))
  cacheHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`)
  const cacheResponse = new Response(cacheStream, {
    status: response.status,
    statusText: response.statusText,
    headers: cacheHeaders
  })
  context.waitUntil((async () => {
    try {
      await cache.put(request, cacheResponse)
    } catch (_) {}
  })())

  return clientResponse
}

export async function onRequestGet(context) {
  const { request } = context
  const url = new URL(request.url)
  const path = url.pathname
  if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405 })
  if (path === '/tur') return new Response(null, { status: 301, headers: { Location: '/tur/' } })
  if (path !== '/tur/') return new Response('Not Found', { status: 404 })
  const upstreamUrl = 'https://tur-mirror.pages.dev/tur/'
  try {
    return await fetchAndStream(upstreamUrl, request, context)
  } catch (err) {
    return new Response('Upstream fetch error: ' + err, { status: 502 })
  }
}

export async function onRequestHead(context) {
  const { request } = context
  const url = new URL(request.url)
  const path = url.pathname
  if (request.method !== 'HEAD') return new Response('Method Not Allowed', { status: 405 })
  if (path === '/tur') return new Response(null, { status: 301, headers: { Location: '/tur/' } })
  if (path !== '/tur/') return new Response('Not Found', { status: 404 })
  const upstreamUrl = 'https://tur-mirror.pages.dev/tur/'
  try {
    const response = await fetchWithRetry(upstreamUrl, { method: 'HEAD' })
    return new Response(null, {
      status: response.status,
      statusText: response.statusText,
      headers: withSecurity(sanitizeHeaders(response.headers))
    })
  } catch (err) {
    return new Response('Upstream HEAD error: ' + err, { status: 502 })
  }
}
