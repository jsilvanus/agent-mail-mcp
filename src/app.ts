import Fastify, { type FastifyInstance } from 'fastify';
import formbody from '@fastify/formbody';
import { GmailConnector } from './connector.js';
import { mountGdprPage, type GdprConfig } from './gdpr.js';
import { mountMcpHttp } from './mcp/http.js';
import { mountOAuthMetadata } from './oauth-metadata.js';
import { mountAuthorizationServer, type AuthorizationServerOptions } from './oauth/authorization-server.js';
import type { AuthStore, UserStore } from './storage/interface.js';

export interface AppOptions {
  publicUrl: string;
  jwtSecret: Uint8Array;
  store: AuthStore;
  users: UserStore;
  gdpr: GdprConfig;
  authorization?: AuthorizationServerOptions;
  logger?: boolean;
}

export async function buildApp(options: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: options.logger ?? true });
  await app.register(formbody);
  const resource = options.publicUrl + '/mcp';
  await mountOAuthMetadata(app, options.publicUrl);
  await mountGdprPage(app, options.gdpr);
  await mountAuthorizationServer(app, options.publicUrl, resource, options.jwtSecret, options.store, options.users, options.authorization);
  await mountMcpHttp(app, { connector: new GmailConnector(), users: options.users, publicUrl: options.publicUrl, jwtSecret: options.jwtSecret, resource });
  app.get('/health', async () => ({ ok: true }));
  return app;
}
