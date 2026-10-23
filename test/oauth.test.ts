/**
 * OAuth integration: Google is the only sign-in entry point. MCP authorization
 * codes remain a separate OAuth/PKCE flow.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.js';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { recipientDigest } from '../src/recipient-hmac.js';

const CLIENT_ID = 'https://client.example/oauth/client.json';
const REDIRECT_URI = 'https://client.example/callback';
let app: FastifyInstance;
let base: string;
let dir: string;
let store: SqliteAuthStore;

before(async () => {
  process.env.AGENT_RECIPIENT_HMAC_SECRET = 'test-recipient-hmac-secret-32-bytes-minimum';
  dir = mkdtempSync(join(tmpdir(), 'agent-mail-mcp-'));
  store = new SqliteAuthStore(join(dir, 'test.sqlite'));
  const users = new SqliteUserStore(store.getDatabase());
  users.createUser({ id: 'test-user-pseudonymous', name: 'Google account', agentRecipientHash: recipientDigest('test+agent@gmail.com'), createdAt: Date.now() });
  app = await buildApp({
    publicUrl: 'http://127.0.0.1',
    jwtSecret: randomBytes(32),
    store,
    users,
    logger: false,
    authorization: {
      fetchClientMetadata: async (clientId: string) => ({ client_id: clientId, client_name: 'Test Client', redirect_uris: [REDIRECT_URI] }),
    },
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  base = typeof address === 'object' && address ? `http://127.0.0.1:${address.port}` : '';
});

after(async () => {
  await app.close();
  rmSync(dir, { recursive: true, force: true });
});

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
function authorizeQuery(challenge: string) {
  return new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', scope: 'mcp',
  });
}
async function postForm(path: string, form: Record<string, string>) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
    redirect: 'manual',
  });
}
async function mcp(token: string | null, body: unknown) {
  const res = await fetch(base + '/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(token ? { authorization: 'Bearer ' + token } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const data = text.split('\n').filter(l => l.startsWith('data: ')).map(l => JSON.parse(l.slice(6)));
  return { status: res.status, headers: res.headers, message: data[0] ?? (text ? JSON.parse(text) : null) };
}

describe('Google sign-in entry point', () => {
  it('redirects valid MCP authorization requests to the Google sign-in consent page', async () => {
    const { challenge } = pkce();
    const res = await fetch(base + '/oauth/authorize?' + authorizeQuery(challenge), { redirect: 'manual' });
    assert.equal(res.status, 302);
    const location = new URL(res.headers.get('location')!, base);
    assert.equal(location.pathname, '/auth/google/start');
    assert.ok(location.searchParams.get('oauth'));
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });

  it('rejects invalid MCP authorization requests', async () => {
    const res = await fetch(base + '/oauth/authorize?response_type=token', { redirect: 'manual' });
    assert.equal(res.status, 400);
  });

  it('does not allow the old local password sign-in endpoint', async () => {
    const res = await postForm('/oauth/authorize', { email: 'someone@example.com', password: 'password' });
    assert.equal(res.status, 405);
  });
});

describe('MCP authorization code and PKCE', () => {
  it('exchanges a one-time code and serves /mcp', async () => {
    const { verifier, challenge } = pkce();
    const code = randomBytes(32).toString('base64url');
    store.saveAuthorizationCode({
      code, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, challenge,
      subject: 'test-user-pseudonymous', scope: 'mcp', expires: Date.now() + 60_000,
    });
    const tokenRes = await postForm('/oauth/token', {
      grant_type: 'authorization_code', code, client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, code_verifier: verifier,
    });
    assert.equal(tokenRes.status, 200);
    const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string };
    assert.ok(tokens.access_token && tokens.refresh_token);

    const init = await mcp(tokens.access_token, {
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
    });
    assert.equal(init.status, 200);
    const list = await mcp(tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.equal(list.status, 200);
    const names = list.message.result.tools.map((t: { name: string }) => t.name);
    assert.ok(names.includes('agent_inbox_list'));
    assert.ok(names.includes('agent_inbox_message'));
  });

  it('rejects an incorrect PKCE verifier and consumes the code', async () => {
    const code = randomBytes(32).toString('base64url');
    store.saveAuthorizationCode({
      code, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, challenge: pkce().challenge,
      subject: 'test-user-pseudonymous', scope: 'mcp', expires: Date.now() + 60_000,
    });
    const bad = await postForm('/oauth/token', {
      grant_type: 'authorization_code', code, client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, code_verifier: 'wrong-verifier',
    });
    assert.equal(bad.status, 400);
    const retry = await postForm('/oauth/token', {
      grant_type: 'authorization_code', code, client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, code_verifier: pkce().verifier,
    });
    assert.equal(retry.status, 400);
  });

  it('answers 401 with WWW-Authenticate without a token', async () => {
    const res = await mcp(null, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate') ?? '', /resource_metadata=/);
  });
});
