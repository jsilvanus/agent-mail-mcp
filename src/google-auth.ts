import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { AuthStore, UserStore } from './storage/interface.js';
import { agentAddressFromAccountEmail, recipientDigest } from './recipient-hmac.js';
import { fetchCimdMetadata, isCimdClientId } from './oauth/cimd.js';

type OAuthQuery = Record<string, string | undefined>;
type Transaction = { nonce: string; oauth: string; expires: number };
type TokenResponse = { access_token?: string; refresh_token?: string; expires_in?: number; id_token?: string; scope?: string; error?: string };

export interface GoogleAuthOptions {
  publicUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tokenEncryptionKey: Buffer;
  identityHmacSecret: Buffer;
  users: UserStore;
  authStore: AuthStore;
}

const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
const GOOGLE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
const transactions = new Map<string, Transaction>();

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
function page(title: string, body: string): string {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escapeHtml(title) +
    '</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f9;margin:0;padding:3rem 1rem}main{max-width:520px;margin:0 auto;background:#fff;padding:2rem;border-radius:12px}button{padding:.8rem 1rem;border:0;border-radius:7px;cursor:pointer;background:#174ea6;color:#fff;font-weight:600}.notice{background:#f3f6fc;padding:1rem;border-radius:8px}label{display:block;margin:1rem 0}</style></head><body><main>' + body + '</main></body></html>';
}
function sendHtml(reply: FastifyReply, html: string, status = 200) {
  return reply.code(status).header('Cache-Control', 'no-store').header('Referrer-Policy', 'no-referrer')
    .header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    .type('text/html; charset=utf-8').send(html);
}
function randomId(): string { return randomBytes(32).toString('base64url'); }
function pseudonymousId(secret: Buffer, issuer: string, sub: string): string {
  return createHmac('sha256', secret).update(issuer + '\0' + sub, 'utf8').digest('hex');
}
function encryptToken(key: Buffer, token: string, userId: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(userId, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return [iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('.');
}
function decryptToken(key: Buffer, value: string, userId: string): string {
  const [iv, tag, ciphertext] = value.split('.');
  if (!iv || !tag || !ciphertext) throw new Error('Stored Google token has an invalid format.');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(userId, 'utf8'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]).toString('utf8');
}
function parseOAuth(value: string): OAuthQuery {
  try { return Object.fromEntries(new URLSearchParams(Buffer.from(value, 'base64url').toString('utf8'))); }
  catch { throw new Error('Invalid MCP OAuth request.'); }
}
function validOAuth(q: OAuthQuery): boolean {
  return q.response_type === 'code' && Boolean(q.client_id && q.redirect_uri && q.code_challenge) && q.code_challenge_method === 'S256' && Boolean(q.client_id && isCimdClientId(q.client_id));
}
async function validateOAuth(q: OAuthQuery): Promise<boolean> {
  if (!validOAuth(q) || !q.client_id || !q.redirect_uri) return false;
  try { const metadata = await fetchCimdMetadata(q.client_id); return metadata.redirect_uris.includes(q.redirect_uri); } catch { return false; }
}

export class GoogleAuthService {
  private readonly db: import('node:sqlite').DatabaseSync;
  private readonly accessTokens = new Map<string, { token: string; expires: number }>();

  constructor(private readonly options: GoogleAuthOptions, db: import('node:sqlite').DatabaseSync) {
    if (options.tokenEncryptionKey.length !== 32) throw new Error('GOOGLE_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes.');
    if (options.identityHmacSecret.length < 32) throw new Error('IDENTITY_HMAC_SECRET must contain at least 32 bytes.');
    this.db = db;
    this.db.exec('CREATE TABLE IF NOT EXISTS google_credentials (user_id TEXT PRIMARY KEY, refresh_token_encrypted TEXT NOT NULL, updated_at INTEGER NOT NULL)');
  }

  private saveCredential(userId: string, token: string): void {
    this.db.prepare('INSERT INTO google_credentials (user_id, refresh_token_encrypted, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET refresh_token_encrypted=excluded.refresh_token_encrypted, updated_at=excluded.updated_at')
      .run(userId, encryptToken(this.options.tokenEncryptionKey, token, userId), Date.now());
    this.accessTokens.delete(userId);
  }

  deleteCredential(userId: string): void {
    this.db.prepare('DELETE FROM google_credentials WHERE user_id = ?').run(userId);
    this.accessTokens.delete(userId);
  }

  pruneInMemoryTokens(): void {
    const now = Date.now();
    for (const [userId, value] of this.accessTokens) {
      if (value.expires <= now || !this.options.users.getUser(userId)) this.accessTokens.delete(userId);
    }
  }

  async accessTokenForUser(userId: string): Promise<string> {
    if (!this.options.users.getUser(userId)) {
      this.deleteCredential(userId);
      throw new Error('This account expired. Sign in again to reconnect Gmail.');
    }
    const cached = this.accessTokens.get(userId);
    if (cached && cached.expires > Date.now() + 60_000) return cached.token;
    const row = this.db.prepare('SELECT refresh_token_encrypted FROM google_credentials WHERE user_id = ?').get(userId) as { refresh_token_encrypted: string } | undefined;
    if (!row) throw new Error('This account has no connected Gmail authorization. Sign in again and grant read-only Gmail access.');
    const refreshToken = decryptToken(this.options.tokenEncryptionKey, row.refresh_token_encrypted, userId);
    const response = await fetch(GOOGLE_TOKEN, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.options.clientId, client_secret: this.options.clientSecret, refresh_token: refreshToken, grant_type: 'refresh_token' }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      if (response.status === 400 || response.status === 401) this.deleteCredential(userId);
      throw new Error('Google access-token refresh failed (' + response.status + '). Reconnect Google if access was revoked.');
    }
    const value = await response.json() as TokenResponse;
    if (!value.access_token) throw new Error('Google token response did not include an access token.');
    this.accessTokens.set(userId, { token: value.access_token, expires: Date.now() + (value.expires_in ?? 3600) * 1000 });
    return value.access_token;
  }

  async mount(app: FastifyInstance): Promise<void> {
    const { publicUrl, clientId, clientSecret, redirectUri, users, authStore } = this.options;
    app.get('/auth/google/start', async (request, reply) => {
      const query = request.query as { oauth?: string };
      if (!query.oauth || query.oauth.length > 8192) return sendHtml(reply, page('Sign in', '<h1>Sign in unavailable</h1><p>Start again from your MCP client.</p>'), 400);
      let q: OAuthQuery;
      try { q = parseOAuth(query.oauth); } catch { return sendHtml(reply, page('Sign in', '<h1>Invalid sign-in request</h1>'), 400); }
      if (!(await validateOAuth(q))) return sendHtml(reply, page('Sign in', '<h1>Invalid sign-in request</h1>'), 400);
      return sendHtml(reply, page('Sign in with Google',
        '<h1>Sign in with Google</h1><p>Agent Mail MCP uses your Google account to identify your account. Your email address and Google profile name are not stored.</p>' +
        '<div class="notice"><h2>Connect Gmail (read-only)</h2><p>To provide the inbox tools, this service needs permission to read Gmail messages. It will not send, delete, or modify messages. Message content is returned only when your MCP client requests it and may then be processed by that client’s configured AI provider.</p></div>' +
        '<form method="post" action="/auth/google/consent"><input type="hidden" name="oauth" value="' + escapeHtml(query.oauth) + '">' +
        '<label><input type="checkbox" name="gmailConsent" value="yes" required> I explicitly authorize Agent Mail MCP to read my Gmail messages for the inbox tools.</label>' +
        '<button type="submit">Continue to Google</button></form>'));
    });

    app.post('/auth/google/consent', async (request, reply) => {
      const body = request.body as { oauth?: string; gmailConsent?: string };
      if (!body.oauth || body.gmailConsent !== 'yes') return sendHtml(reply, page('Consent required', '<h1>Consent required</h1><p>Gmail read-only consent is required to continue.</p><p><a href="/auth/google/start?oauth=' + encodeURIComponent(body.oauth ?? '') + '">Try again</a></p>'), 400);
      let q: OAuthQuery;
      try { q = parseOAuth(body.oauth); } catch { return sendHtml(reply, page('Invalid request', '<h1>Invalid request</h1>'), 400); }
      if (!(await validateOAuth(q))) return sendHtml(reply, page('Invalid request', '<h1>Invalid request</h1>'), 400);
      for (const [key, value] of transactions) if (value.expires <= Date.now()) transactions.delete(key);
      const state = randomId(), nonce = randomId();
      transactions.set(state, { nonce, oauth: body.oauth, expires: Date.now() + 10 * 60_000 });
      const target = new URL(GOOGLE_AUTH);
      target.search = new URLSearchParams({
        client_id: clientId, redirect_uri: redirectUri, response_type: 'code',
        scope: 'openid email profile https://www.googleapis.com/auth/gmail.readonly',
        access_type: 'offline', prompt: 'consent', include_granted_scopes: 'false',
        state, nonce,
      }).toString();
      return reply.redirect(target.toString());
    });

    app.get('/auth/google/callback', async (request, reply) => {
      const q = request.query as { code?: string; state?: string; error?: string };
      const transaction = q.state ? transactions.get(q.state) : undefined;
      if (q.state) transactions.delete(q.state);
      if (q.error || !q.code || !transaction || transaction.expires < Date.now()) {
        return sendHtml(reply, page('Google sign-in failed', '<h1>Google sign-in failed</h1><p>No account was created. Return to your MCP client and try again.</p>'), 400);
      }
      try {
        const tokenResponse = await fetch(GOOGLE_TOKEN, {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ code: q.code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' }),
          signal: AbortSignal.timeout(10_000),
        });
        if (!tokenResponse.ok) throw new Error('Google code exchange failed.');
        const tokens = await tokenResponse.json() as TokenResponse;
        if (!tokens.id_token || !tokens.refresh_token || (tokens.scope && !tokens.scope.split(' ').includes('https://www.googleapis.com/auth/gmail.readonly'))) throw new Error('Google did not return the required identity and offline Gmail read-only authorization.');
        const { payload } = await jwtVerify(tokens.id_token, GOOGLE_JWKS, { audience: clientId, issuer: GOOGLE_ISSUERS });
        if (payload.nonce !== transaction.nonce || typeof payload.sub !== 'string' || typeof payload.email !== 'string' || payload.email_verified !== true) {
          throw new Error('Google identity verification failed.');
        }
        const email = payload.email;
        const id = pseudonymousId(this.options.identityHmacSecret, typeof payload.iss === 'string' ? payload.iss : 'https://accounts.google.com', payload.sub);
        const digest = recipientDigest(agentAddressFromAccountEmail(email));
        let user = users.getUser(id);
        if (!user) {
          users.createUser({ id, name: 'Google account', agentRecipientHash: digest, createdAt: Date.now() });
          user = users.getUser(id);
        }
        if (!user) throw new Error('Could not create the local account.');
        this.saveCredential(id, tokens.refresh_token);
        const oauth = parseOAuth(transaction.oauth);
        if (!validOAuth(oauth) || !oauth.client_id || !oauth.redirect_uri || !oauth.code_challenge) throw new Error('MCP authorization request is invalid.');
        const code = randomId();
        authStore.saveAuthorizationCode({
          code, clientId: oauth.client_id, redirectUri: oauth.redirect_uri,
          challenge: oauth.code_challenge, subject: id, scope: oauth.scope ?? 'mcp',
          expires: Date.now() + 60_000,
        });
        const target = new URL(oauth.redirect_uri);
        target.searchParams.set('code', code);
        target.searchParams.set('iss', publicUrl);
        if (oauth.state) target.searchParams.set('state', oauth.state);
        return reply.redirect(target.toString());
      } catch (error) {
        request.log.warn({ err: error }, 'Google sign-in failed');
        return sendHtml(reply, page('Google sign-in failed', '<h1>Google sign-in failed</h1><p>No authorization code was issued. Check the server configuration and try again.</p>'), 400);
      }
    });
  }
}
