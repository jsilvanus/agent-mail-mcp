import { hash } from '@node-rs/argon2';
import { buildApp } from './app.js';
import { SqliteAuthStore, SqliteUserStore } from './storage/sqlite.js';
import { SqliteMetadataCache } from './storage/metadata-cache.js';

const port = Number(process.env.PORT ?? '5999');
const publicUrl = process.env.MCP_PUBLIC_URL ?? ('http://localhost:' + port);
const secretText = process.env.JWT_SECRET;
const defaultUserPassword = process.env.MCP_DEFAULT_USER_PASSWORD;

if (!Number.isInteger(port) || port <= 0) throw new Error('Invalid PORT: ' + process.env.PORT);
if (!secretText) throw new Error('JWT_SECRET is required');
if (!defaultUserPassword) throw new Error('MCP_DEFAULT_USER_PASSWORD is required');

const secret = Buffer.from(secretText, 'base64');
if (secret.length < 32) throw new Error('JWT_SECRET must decode to at least 32 bytes');

const storagePath = process.env.STORAGE_PATH ?? './data/app.sqlite';
const store = new SqliteAuthStore(storagePath);
const users = new SqliteUserStore(store.getDatabase());
const metadataCache = new SqliteMetadataCache(store.getDatabase(), secret);
metadataCache.pruneExpired();
users.pruneInactiveUsers();
const defaultUserId = process.env.MCP_DEFAULT_USER_ID ?? 'demo-user';
const defaultUserEmail = process.env.MCP_DEFAULT_USER_EMAIL ?? 'demo@example.com';
if (!users.getUser(defaultUserId)) {
  users.createUser({ id: defaultUserId, name: 'Agent Mail MCP Admin', email: defaultUserEmail, passwordHash: await hash(defaultUserPassword, { algorithm: 2 }), createdAt: Date.now() });
}

const app = await buildApp({ publicUrl, jwtSecret: secret, store, users, metadataCache });
await app.listen({ host: process.env.HOST ?? '0.0.0.0', port });
