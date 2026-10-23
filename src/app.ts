import Fastify, { type FastifyInstance } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import formbody from '@fastify/formbody';
import { GmailConnector } from './connector.js';
import { mountGdprPage, type GdprConfig } from './gdpr.js';
import { mountTermsPage } from './terms.js';
import type { SqliteUsageMetrics } from './storage/usage-metrics.js';
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
  metrics?: SqliteUsageMetrics;
  metricsAdminToken?: string;
  logger?: boolean;
}

export async function buildApp(options: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: options.logger ?? true });
  await app.register(formbody);
  const resource = options.publicUrl + '/mcp';
  await mountOAuthMetadata(app, options.publicUrl);
  await mountGdprPage(app, options.gdpr);
  await mountTermsPage(app);
  await mountAuthorizationServer(app, options.publicUrl, resource, options.jwtSecret, options.store, options.users, options.authorization);
  await mountMcpHttp(app, { connector: new GmailConnector(), users: options.users, metrics: options.metrics, publicUrl: options.publicUrl, jwtSecret: options.jwtSecret, resource });
  if (options.metrics && options.metricsAdminToken) {
    app.get('/admin/metrics', async (request, reply) => {
      const supplied = request.headers['x-metrics-token'];
      const token = Array.isArray(supplied) ? supplied[0] : supplied;
      if (!token) return reply.code(404).send({ error: 'not_found' });
      const a = Buffer.from(token), b = Buffer.from(options.metricsAdminToken!);
      if (a.length !== b.length || !timingSafeEqual(a, b)) return reply.code(404).send({ error: 'not_found' });
      const users = options.users.listUsers();
      return reply.header('Cache-Control', 'no-store').send(options.metrics!.snapshot(users.length));
    });
  }
  app.get('/health', async () => ({ ok: true }));
  return app;
}
