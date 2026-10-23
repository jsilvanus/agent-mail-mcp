import type { FastifyInstance, FastifyReply } from 'fastify';
import type { AuthStore, UserStore } from '../storage/interface.js';
import { fetchCimdMetadata, isCimdClientId, type CimdMetadata } from './cimd.js';
import { randomToken, verifyS256 } from './pkce.js';
import { issueAccessToken } from './jwt.js';
import { contentSecurityPolicy } from '../csp.js';

export type { CimdMetadata };

export interface AuthorizationServerOptions {
  /** Resolves a CIMD client_id to its metadata. Replaceable in tests. */
  fetchClientMetadata?: (clientId: string) => Promise<CimdMetadata>;
}

function escapeHtml(value: string): string {
  return value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'","&#39;");
}

function page(title: string, body: string): string {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' +
    escapeHtml(title) +
    '</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f9;margin:0;padding:4rem 1rem}main{max-width:420px;margin:0 auto;background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}h1{margin-top:0}label{display:block;margin:.9rem 0 .35rem}input{display:block;width:100%;box-sizing:border-box;padding:.7rem;border:1px solid #ccc;border-radius:7px}button{margin-top:1rem;padding:.7rem 1.1rem;border:0;border-radius:7px;cursor:pointer}.secondary{margin-left:.5rem;background:#eee}.error{color:#b00020}</style></head><body><main>' +
    body +
    '</main></body></html>';
}

function encodeOAuth(query: Record<string,string|undefined>): string {
  return Buffer.from(new URLSearchParams(Object.entries(query).filter((entry): entry is [string,string] => typeof entry[1] === 'string')).toString()).toString('base64url');
}

function sendHtml(reply: FastifyReply, html: string, formAction: string[] = [], status = 200) {
  return reply.code(status).header('Content-Security-Policy', contentSecurityPolicy(formAction)).header('Cache-Control', 'no-store').type('text/html').send(html);
}

export async function mountAuthorizationServer(
  app: FastifyInstance,
  issuer: string,
  resource: string,
  secret: Uint8Array,
  authStore: AuthStore,
  users: UserStore,
  options: AuthorizationServerOptions = {},
): Promise<void> {
  const fetchClientMetadata = options.fetchClientMetadata ?? fetchCimdMetadata;

  async function validateRequest(query: Record<string,string|undefined>) {
    if (query.response_type !== 'code' || !query.client_id || !query.redirect_uri || !query.code_challenge || query.code_challenge_method !== 'S256') {
      throw new Error('Invalid OAuth request');
    }
    if (!isCimdClientId(query.client_id)) throw new Error('Invalid client_id');
    const metadata = await fetchClientMetadata(query.client_id);
    if (!metadata.redirect_uris.includes(query.redirect_uri)) throw new Error('Invalid redirect_uri');
    return metadata;
  }

  app.get('/oauth/authorize', async (request, reply) => {
    const q = request.query as Record<string,string|undefined>;
    try {
      await validateRequest(q);
      return reply.redirect('/auth/google/start?oauth=' + encodeURIComponent(encodeOAuth(q)));
    } catch {
      return sendHtml(reply, page('Invalid request','<h1>Invalid authorization request</h1>'), [], 400);
    }
  });

  // User authentication is Google OIDC only. Local email/password sign-in is intentionally disabled.
  app.post('/oauth/authorize', async (_request, reply) => {
    return sendHtml(reply, page('Google sign-in required', '<h1>Continue with Google</h1><p>Start the authorization flow again and sign in with Google.</p>'), [], 405);
  });

  app.post('/oauth/token', async (request, reply) => {
    const b = request.body as Record<string,string|undefined>;
    reply.header('Cache-Control', 'no-store'); // RFC 6749 §5.1

    if (b.grant_type === 'authorization_code') {
      const code = b.code ? authStore.consumeAuthorizationCode(b.code) : undefined;
      if (!code || b.client_id !== code.clientId || b.redirect_uri !== code.redirectUri || !b.code_verifier || !verifyS256(b.code_verifier,code.challenge)) {
        return reply.code(400).send({error:'invalid_grant'});
      }
      const access = await issueAccessToken(secret,issuer,resource,code.subject,code.clientId,code.scope);
      const refreshToken = randomToken();
      authStore.saveRefreshToken({token:refreshToken,clientId:code.clientId,subject:code.subject,scope:code.scope,expires:Date.now()+30*86_400_000});
      return {access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refreshToken,scope:code.scope};
    }

    if (b.grant_type === 'refresh_token') {
      const refreshToken = b.refresh_token ? authStore.getRefreshToken(b.refresh_token) : undefined;
      if (!refreshToken || b.client_id !== refreshToken.clientId) return reply.code(400).send({error:'invalid_grant'});
      // A deleted user keeps no access through old refresh tokens
      if (!users.getUser(refreshToken.subject)) return reply.code(400).send({error:'invalid_grant'});
      const access = await issueAccessToken(secret,issuer,resource,refreshToken.subject,refreshToken.clientId,refreshToken.scope);
      return {access_token:access,token_type:'Bearer',expires_in:3600,scope:refreshToken.scope};
    }

    return reply.code(400).send({error:'unsupported_grant_type'});
  });
}
