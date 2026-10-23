import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.js';
import { GoogleAuthService } from '../src/google-auth.js';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';

const CLIENT_ID = 'https://client.example/oauth/client.json';
const REDIRECT_URI = 'https://client.example/callback';
let app: FastifyInstance;
let base: string;
let dir: string;
let users: SqliteUserStore;

const gdpr = {
  controllerName: 'Test controller', controllerAddress: 'Test address',
  controllerEmail: 'controller@example.com', privacyContactEmail: 'privacy@example.com',
  hostingCountry: 'Finland', purposes: 'Test purpose', lawfulBasis: 'Test lawful basis',
  retention: 'Test retention', recipients: 'Test recipients',
  internationalTransfers: 'Test transfer policy', supervisoryAuthority: 'Test authority',
};

before(async () => {
  process.env.AGENT_RECIPIENT_HMAC_SECRET = 'test-recipient-hmac-secret-32-bytes-minimum';
  dir = mkdtempSync(join(tmpdir(), 'agent-mail-google-auth-'));
  const store = new SqliteAuthStore(join(dir, 'test.sqlite'));
  users = new SqliteUserStore(store.getDatabase());
  const publicUrl = 'http://127.0.0.1';
  const metadata = async (clientId: string) => ({ client_id: clientId, client_name: 'Test MCP client', redirect_uris: [REDIRECT_URI] });
  const googleAuth = new GoogleAuthService({
    publicUrl, clientId: 'test-google-client-id', clientSecret: 'test-google-client-secret',
    redirectUri: publicUrl + '/auth/google/callback',
    tokenEncryptionKey: randomBytes(32), identityHmacSecret: randomBytes(32),
    users, authStore: store, fetchClientMetadata: metadata,
  }, store.getDatabase());
  app = await buildApp({
    publicUrl, jwtSecret: randomBytes(32), store, users, gdpr, googleAuth, logger: false,
    authorization: { fetchClientMetadata: metadata },
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  base = typeof address === 'object' && address ? `http://127.0.0.1:${address.port}` : '';
});

after(async () => {
  await app.close();
  rmSync(dir, { recursive: true, force: true });
});

function oauthValue() {
  return Buffer.from(new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    code_challenge: randomBytes(32).toString('base64url'),
    code_challenge_method: 'S256', state: 'mcp-state', scope: 'mcp',
  }).toString()).toString('base64url');
}

async function postForm(form: Record<string, string>) {
  return fetch(base + '/auth/google/consent', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form), redirect: 'manual',
  });
}

describe('Google OAuth onboarding', () => {
  it('shows a distinct, explicit Gmail read-only consent step', async () => {
    const res = await fetch(base + '/auth/google/start?oauth=' + encodeURIComponent(oauthValue()));
    const html = await res.text();
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.match(html, /Gmail \(read-only\)/);
    assert.match(html, /name="gmailConsent"/);
    assert.match(html, /required/);
    assert.match(html, /will not send, delete, or modify messages/);
    assert.match(html, /email address and Google profile name are not stored/);
  });

  it('refuses to continue unless explicit Gmail consent is submitted', async () => {
    const res = await postForm({ oauth: oauthValue() });
    assert.equal(res.status, 400);
    assert.equal(users.listUsers().length, 0);
  });

  it('redirects to Google with OIDC nonce, state, and Gmail read-only scope after consent', async () => {
    const res = await postForm({ oauth: oauthValue(), gmailConsent: 'yes' });
    assert.equal(res.status, 302);
    const target = new URL(res.headers.get('location')!);
    assert.equal(target.origin, 'https://accounts.google.com');
    assert.equal(target.pathname, '/o/oauth2/v2/auth');
    assert.equal(target.searchParams.get('response_type'), 'code');
    assert.ok(target.searchParams.get('state'));
    assert.ok(target.searchParams.get('nonce'));
    assert.ok(target.searchParams.get('scope')?.includes('https://www.googleapis.com/auth/gmail.readonly'));
    assert.equal(target.searchParams.get('access_type'), 'offline');
    assert.equal(users.listUsers().length, 0);
  });

  it('does not create an account for an invalid or expired callback state', async () => {
    const res = await fetch(base + '/auth/google/callback?code=fake&state=not-a-real-state', { redirect: 'manual' });
    assert.equal(res.status, 400);
    assert.equal(users.listUsers().length, 0);
  });
});
