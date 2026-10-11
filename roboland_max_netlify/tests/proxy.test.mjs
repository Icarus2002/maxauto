import test from 'node:test';
import assert from 'node:assert/strict';
import handler, { normalizeTargetPath, isAllowedRoute } from '../netlify/functions/max-proxy.mjs';

test('routes match Apps Script MAX operations', () => {
  for (const [method, path] of [
    ['GET','/me'], ['GET','/chats/-76076071268440'], ['GET','/subscriptions'],
    ['GET','/updates'], ['POST','/messages'], ['POST','/uploads'],
    ['POST','/subscriptions']
  ]) assert.equal(isAllowedRoute(method, path), true, `${method} ${path}`);
  assert.equal(isAllowedRoute('GET', '/metadata'), false);
  assert.equal(isAllowedRoute('POST', '/chats/-123'), false);
});

test('path normalization rejects traversal and misplaced URL', () => {
  assert.equal(normalizeTargetPath('chats%2F-123'), '/chats/-123');
  assert.equal(normalizeTargetPath('messages'), '/messages');
  assert.equal(normalizeTargetPath('..%2Fme'), null);
  assert.equal(normalizeTargetPath('https:%2F%2Fevil.example'), null);
});

test('health can be read without token and does not contact MAX', async () => {
  const r = await handler(new Request('https://example.netlify.app/.netlify/functions/max-proxy?max_path=health'));
  assert.equal(r.status, 200);
  assert.equal((await r.json()).status, 'running');
});

test('unauthorized requests cannot be proxied', async () => {
  process.env.MAX_BOT_TOKEN = 'TEST_TOKEN_NOT_REAL';
  const r = await handler(new Request('https://example.netlify.app/.netlify/functions/max-proxy?max_path=me'));
  assert.equal(r.status, 401);
  assert.equal((await r.json()).error, 'PROXY_UNAUTHORIZED');
});
