import { hash } from '@node-rs/argon2';
import { buildApp } from './app.js';
import { loadGdprConfig } from './gdpr.js';
import { validateRecipientSecret } from './recipient-hmac.js';
import { SqliteAuthStore, SqliteUserStore } from './storage/sqlite.js';
import { SqliteUsageMetrics } from './storage/usage-metrics.js';

const port = Number(process.env.PORT ?? '5999');
const publicUrl = process.env.MCP_PUBLIC_URL ?? ('http://localhost:' + port);
const secretText = process.env.JWT_SECRET;
const defaultUserPassword = process.env.MCP_DEFAULT_USER_PASSWORD;
const metricsSecretText = process.env.METRICS_HMAC_SECRET;
const metricsAdminToken = process.env.METRICS_ADMIN_TOKEN;
const gdpr = loadGdprConfig();
validateRecipientSecret();

if (!Number.isInteger(port) || port <= 0) throw new Error('Invalid PORT: ' + process.env.PORT);
if (!secretText) throw new Error('JWT_SECRET is required');
if (!defaultUserPassword) throw new Error('MCP_DEFAULT_USER_PASSWORD is required');
if (metricsSecretText && Buffer.byteLength(metricsSecretText, 'utf8') < 32) throw new Error('METRICS_HMAC_SECRET must contain at least 32 UTF-8 bytes.');
if (metricsAdminToken && metricsAdminToken.length < 32) throw new Error('METRICS_ADMIN_TOKEN must contain at least 32 characters.');

const secret = Buffer.from(secretText, 'base64');
if (secret.length < 32) throw new Error('JWT_SECRET must decode to at least 32 bytes');

const storagePath = process.env.STORAGE_PATH ?? './data/app.sqlite';
const store = new SqliteAuthStore(storagePath);
const users = new SqliteUserStore(store.getDatabase());
const metrics = metricsSecretText ? new SqliteUsageMetrics(store.getDatabase(), Buffer.from(metricsSecretText, 'utf8')) : undefined;
users.pruneInactiveUsers();
const userPruneTimer = setInterval(() => {
  try { users.pruneInactiveUsers(); }
  catch { console.error('Failed to prune inactive user records.'); }
}, 60 * 60 * 1000);
userPruneTimer.unref();
const defaultUserId = process.env.MCP_DEFAULT_USER_ID ?? 'demo-user';
const defaultUserEmail = process.env.MCP_DEFAULT_USER_EMAIL ?? 'demo@example.com';
// Bootstrap the configured local user only once. Otherwise an expired/deleted user
// would be recreated on every restart and the inactivity TTL would be ineffective.
const db = store.getDatabase();
db.exec('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
const bootstrap = db.prepare("SELECT value FROM app_settings WHERE key = 'default_user_bootstrap_done'").get() as { value: string } | undefined;
if (!bootstrap) {
  if (users.listUsers().length === 0 && !users.getUser(defaultUserId)) {
    users.createUser({ id: defaultUserId, name: 'Agent Mail MCP Admin', email: defaultUserEmail, passwordHash: await hash(defaultUserPassword, { algorithm: 2 }), createdAt: Date.now() });
  }
  db.prepare("INSERT INTO app_settings (key, value) VALUES ('default_user_bootstrap_done', '1')").run();
}

const app = await buildApp({ publicUrl, jwtSecret: secret, store, users, gdpr, metrics, metricsAdminToken });
await app.listen({ host: process.env.HOST ?? '0.0.0.0', port });
