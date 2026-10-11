/**
 * MAX API proxy for Netlify Functions.
 * Fixed upstream host, strict route allowlist, bot-token access control.
 * The token is passed by Google Apps Script as its existing Authorization header.
 * The same token is verified against MAX_BOT_TOKEN stored in Netlify environment.
 * Do not place credentials in this file.
 */
import https from 'node:https';
import tls from 'node:tls';
import { createHash, timingSafeEqual } from 'node:crypto';

const MAX_HOST = 'platform-api2.max.ru';
const MAX_TIMEOUT_MS = 25_000;
const MAX_BODY_BYTES = 2_000_000; // JSON only, images do NOT pass through this proxy.
const MAX_RESPONSE_BYTES = 4_000_000;

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff'
});

function json(status, data) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

export function normalizeTargetPath(raw) {
  if (typeof raw !== 'string' || !raw || raw.length > 120) return null;
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { return null; }
  if (decoded.includes('?') || decoded.includes('#') || decoded.includes(':') || decoded.includes('\\') || decoded.includes('..')) {
    return null;
  }
  const path = '/' + decoded.replace(/^\/+/, '');
  return path;
}

export function isAllowedRoute(method, path) {
  if (method === 'GET' && (path === '/me' || path === '/subscriptions' || path === '/updates')) return true;
  if (method === 'GET' && /^\/chats\/-?\d+$/.test(path)) return true;
  if (method === 'POST' && (path === '/messages' || path === '/uploads' || path === '/subscriptions')) return true;
  if (method === 'DELETE' && path === '/subscriptions') return true;
  return false;
}

function authorized(value, expected) {
  if (!expected || !value) return false;
  // Constant-time compare of fixed-length digests, even for unequal token lengths.
  const a = createHash('sha256').update(value).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

function makeTlsOptions() {
  const result = {
    servername: MAX_HOST,
    rejectUnauthorized: true
  };
  const pemB64 = process.env.MAX_EXTRA_CA_PEM_BASE64 || '';
  if (pemB64) {
    const pem = Buffer.from(pemB64, 'base64').toString('utf8');
    if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('MAX_EXTRA_CA_PEM_BASE64 is invalid');
    }
    // Preserve existing public roots and add the extra trusted CA.
    result.ca = [...tls.rootCertificates, pem];
  }
  // Emergency compatibility only. Do not enable for long-term production.
  if (process.env.ALLOW_UNVERIFIED_MAX_TLS === 'true') {
    result.rejectUnauthorized = false;
  }
  return result;
}

async function fetchMax(path, method, headers, bytes) {
  return new Promise((resolve, reject) => {
    const tlsOpts = makeTlsOptions();
    const req = https.request({
      hostname: MAX_HOST,
      port: 443,
      path,
      method,
      headers,
      ...tlsOpts,
      timeout: MAX_TIMEOUT_MS
    }, (upstream) => {
      const buffers = [];
      let total = 0;
      upstream.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) {
          upstream.destroy(Object.assign(new Error('MAX response too large'), { code: 'RESPONSE_TOO_LARGE' }));
          return;
        }
        buffers.push(chunk);
      });
      upstream.on('end', () => resolve({
        status: upstream.statusCode || 502,
        contentType: upstream.headers['content-type'] || 'application/json; charset=utf-8',
        body: Buffer.concat(buffers)
      }));
      upstream.on('error', reject);
    });
    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Upstream timeout'), { code: 'MAX_TIMEOUT' }));
    });
    req.on('error', reject);
    if (bytes) req.write(bytes);
    req.end();
  });
}

export default async function handler(request) {
  const url = new URL(request.url);
const rawPath = url.pathname.startsWith('/api/')
  ? url.pathname.slice('/api/'.length)
  : url.searchParams.get('max_path');
  const path = normalizeTargetPath(rawPath);
  const method = request.method.toUpperCase();

  // Does not contact MAX or reveal secrets. Only shows that the function deployed.
  if (method === 'GET' && path === '/health') {
    return json(200, {
      status: 'running',
      tokenConfigured: Boolean(process.env.MAX_BOT_TOKEN),
      tlsVerification: process.env.ALLOW_UNVERIFIED_MAX_TLS === 'true' ? 'disabled-for-MAX-only' : 'enabled'
    });
  }

  if (!process.env.MAX_BOT_TOKEN) {
    return json(503, { error: 'NETLIFY_MISSING_MAX_BOT_TOKEN' });
  }

  if (!authorized(request.headers.get('authorization') || '', process.env.MAX_BOT_TOKEN)) {
    return json(401, { error: 'PROXY_UNAUTHORIZED' });
  }

  if (!path || !isAllowedRoute(method, path)) {
    return json(404, { error: 'PROXY_ROUTE_NOT_ALLOWED' });
  }

  const params = new URLSearchParams(url.search);
  params.delete('max_path');
  const qs = params.toString();
  const target = path + (qs ? '?' + qs : '');

  let bytes;
  if (method !== 'GET' && method !== 'HEAD') {
    bytes = Buffer.from(await request.arrayBuffer());
    if (bytes.length > MAX_BODY_BYTES) {
      return json(413, { error: 'JSON_REQUEST_TOO_LARGE' });
    }
  }

  const headers = {
    Authorization: request.headers.get('authorization'),
    Accept: 'application/json',
    'Accept-Encoding': 'identity'
  };
  const contentType = request.headers.get('content-type');
  if (contentType) headers['Content-Type'] = contentType;
  if (bytes?.length) headers['Content-Length'] = String(bytes.length);

  try {
    const upstream = await fetchMax(target, method, headers, bytes);
    return new Response([204, 205, 304].includes(upstream.status) ? null : upstream.body, {
      status: upstream.status,
      headers: {
        'content-type': upstream.contentType,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff'
      }
    });
  } catch (err) {
    // Never log the Authorization header or the bot token.
    const code = String(err?.code || 'UNKNOWN');
    console.error('MAX connection failed, code:', code);
    return json(502, { error: 'MAX_UPSTREAM_FAILED', reason: code });
  }
}

export const config = {
  path: "/api/*"
};

