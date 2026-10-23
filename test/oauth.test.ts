/**
 * End-to-end: sign in on the OAuth page → consent → PKCE token exchange →
 * /mcp. The CIMD client metadata fetch is stubbed.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { hash } from '@node-rs/argon2';
import { buildApp } from '../src/app.js';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';

const CLIENT_ID = 'https://client.example/oauth/client.json';
const REDIRECT_URI = 'https://client.example/callback';
const EMAIL = 'test@example.com';
const PASSWORD = 'correct-horse-battery';

let app: FastifyInstance;
let base: string;
let dir: string;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'api-connector-style-'));
  const store = new SqliteAuthStore(join(dir, 'test.sqlite'));
  const users = new SqliteUserStore(store.getDatabase());
  users.createUser({ id: 'test-user', name: 'Test User', email: EMAIL, passwordHash: await hash(PASSWORD, { algorithm: 2 }), createdAt: Date.now() });
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

// Tokens are bound to the configured public URL; requests go to the ephemeral port.
function authorizeQuery(challenge: string) {
  return new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'xyz',
    scope: 'mcp',
    resource: 'http://127.0.0.1/mcp',
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

const hidden = (html: string, name: string) => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1];

async function signInPage(challenge: string) {
  const res = await fetch(base + '/oauth/authorize?' + authorizeQuery(challenge));
  const html = await res.text();
  return { res, html, oauth: hidden(html, 'oauth')! };
}

async function signIn(oauth: string) {
  const res = await postForm('/oauth/authorize', { oauth, email: EMAIL, password: PASSWORD });
  assert.equal(res.status, 200);
  return { res, html: await res.text() };
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

describe('OAuth authorization flow', () => {
  it('signs in, asks for consent, issues tokens and serves /mcp', async () => {
    const { verifier, challenge } = pkce();
    const page = await signInPage(challenge);
    assert.equal(page.res.status, 200);
    assert.equal(page.res.headers.get('cache-control'), 'no-store');

    const { res, html } = await signIn(page.oauth);
    assert.match(html, /Test Client/);
    assert.match(html, /Test User/);
    // The consent page must allow the redirect to the client
    assert.match(res.headers.get('content-security-policy') ?? '', /https:\/\/client\.example/);
    const ticket = hidden(html, 'ticket');
    assert.ok(ticket);

    const approved = await postForm('/oauth/authorize', { oauth: page.oauth, ticket, action: 'approve' });
    assert.equal(approved.status, 302);
    const location = new URL(approved.headers.get('location')!);
    assert.equal(location.origin + location.pathname, REDIRECT_URI);
    assert.equal(location.searchParams.get('state'), 'xyz');
    assert.equal(location.searchParams.get('iss'), 'http://127.0.0.1');
    const code = location.searchParams.get('code');
    assert.ok(code);

    const tokenRes = await postForm('/oauth/token', {
      grant_type: 'authorization_code', code, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, code_verifier: verifier,
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

  it('redirects with access_denied when the user denies', async () => {
    const page = await signInPage(pkce().challenge);
    const { html } = await signIn(page.oauth);
    const res = await postForm('/oauth/authorize', { oauth: page.oauth, ticket: hidden(html, 'ticket')!, action: 'deny' });
    assert.equal(res.status, 302);
    assert.equal(new URL(res.headers.get('location')!).searchParams.get('error'), 'access_denied');
  });

  it('rejects a wrong password', async () => {
    const { oauth } = await signInPage(pkce().challenge);
    const res = await postForm('/oauth/authorize', { oauth, email: EMAIL, password: 'wrong-password' });
    assert.equal(res.status, 401);
  });

  it('rejects consent without a valid login ticket', async () => {
    const { oauth } = await signInPage(pkce().challenge);
    assert.equal((await postForm('/oauth/authorize', { oauth, action: 'approve' })).status, 401);
    assert.equal((await postForm('/oauth/authorize', { oauth, action: 'approve', ticket: 'forged' })).status, 401);
  });

  it('does not accept a ticket issued for another authorization request', async () => {
    const first = await signInPage(pkce().challenge);
    const ticket = hidden((await signIn(first.oauth)).html, 'ticket')!;
    const second = await signInPage(pkce().challenge);
    assert.equal((await postForm('/oauth/authorize', { oauth: second.oauth, ticket, action: 'approve' })).status, 401);
  });
});

describe('MCP', () => {
  it('answers 401 with WWW-Authenticate without a token', async () => {
    const res = await mcp(null, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate') ?? '', /resource_metadata=/);
  });
});
