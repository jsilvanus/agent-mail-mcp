import { buildApp } from './app.js';
import { loadGdprConfig } from './gdpr.js';
import { validateRecipientSecret } from './recipient-hmac.js';
import { SqliteAuthStore, SqliteUserStore } from './storage/sqlite.js';
import { SqliteUsageMetrics } from './storage/usage-metrics.js';
import { GoogleAuthService } from './google-auth.js';

const port = Number(process.env.PORT ?? '5999');
const publicUrl = process.env.MCP_PUBLIC_URL ?? ('http://localhost:' + port);
const secretText = process.env.JWT_SECRET;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const googleRedirectUri = process.env.GOOGLE_REDIRECT_URI ?? (publicUrl + '/auth/google/callback');
const googleEncryptionKeyText = process.env.GOOGLE_TOKEN_ENCRYPTION_KEY;
const identityHmacSecret = process.env.IDENTITY_HMAC_SECRET;
const metricsSecretText = process.env.METRICS_HMAC_SECRET;
const metricsAdminToken = process.env.METRICS_ADMIN_TOKEN;
const gdpr = loadGdprConfig();
validateRecipientSecret();

if (!Number.isInteger(port) || port <= 0) throw new Error('Invalid PORT: ' + process.env.PORT);
if (!secretText) throw new Error('JWT_SECRET is required');
if (!googleClientId || !googleClientSecret) throw new Error('GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required.');
if (!googleEncryptionKeyText || Buffer.from(googleEncryptionKeyText, 'base64').length !== 32) throw new Error('GOOGLE_TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
if (!identityHmacSecret || Buffer.byteLength(identityHmacSecret, 'utf8') < 32) throw new Error('IDENTITY_HMAC_SECRET must contain at least 32 UTF-8 bytes.');
if (googleRedirectUri !== publicUrl + '/auth/google/callback') throw new Error('GOOGLE_REDIRECT_URI must exactly equal MCP_PUBLIC_URL + /auth/google/callback.');
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
const googleAuth = new GoogleAuthService({
  publicUrl,
  clientId: googleClientId,
  clientSecret: googleClientSecret,
  redirectUri: googleRedirectUri,
  tokenEncryptionKey: Buffer.from(googleEncryptionKeyText, 'base64'),
  identityHmacSecret: Buffer.from(identityHmacSecret, 'utf8'),
  users,
  authStore: store,
}, store.getDatabase());

const app = await buildApp({ publicUrl, jwtSecret: secret, store, users, gdpr, metrics, metricsAdminToken, googleAuth });
await app.listen({ host: process.env.HOST ?? '0.0.0.0', port });
