import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { agentAddressFromAccountEmail, recipientDigest } from '../recipient-hmac.js';
import { DatabaseSync } from 'node:sqlite';
import type { AuthStore, AuthorizationCodeRecord, RefreshTokenRecord, McpUser, UserStore } from './interface.js';

export class SqliteAuthStore implements AuthStore {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, created_at INTEGER NOT NULL, last_tool_call_at INTEGER, agent_recipient_hash TEXT);' +
      'CREATE TABLE IF NOT EXISTS authorization_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);'
    );
    try { this.db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE users ADD COLUMN last_tool_call_at INTEGER'); } catch { /* already exists */ }
    try { this.db.exec('ALTER TABLE users ADD COLUMN agent_recipient_hash TEXT'); } catch { /* already exists */ }
    // Remove encrypted headers persisted by older versions; current code never writes message headers to SQLite.
    const legacyCache = this.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'gmail_metadata_cache'").get();
    if (legacyCache) this.db.exec('DELETE FROM gmail_metadata_cache');
  }

  getDatabase(): DatabaseSync {
    return this.db;
  }

  saveAuthorizationCode(record: AuthorizationCodeRecord): void {
    this.db.prepare('INSERT INTO authorization_codes (code, client_id, redirect_uri, challenge, subject, scope, expires) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(record.code, record.clientId, record.redirectUri, record.challenge, record.subject, record.scope, record.expires);
  }

  consumeAuthorizationCode(code: string): AuthorizationCodeRecord | undefined {
    const row = this.db.prepare('SELECT code, client_id, redirect_uri, challenge, subject, scope, expires FROM authorization_codes WHERE code = ? AND expires >= ?')
      .get(code, Date.now()) as {code:string;client_id:string;redirect_uri:string;challenge:string;subject:string;scope:string;expires:number}|undefined;
    if (!row) {
      this.db.prepare('DELETE FROM authorization_codes WHERE code = ?').run(code);
      return undefined;
    }
    this.db.prepare('DELETE FROM authorization_codes WHERE code = ?').run(code);
    return { code: row.code, clientId: row.client_id, redirectUri: row.redirect_uri, challenge: row.challenge, subject: row.subject, scope: row.scope, expires: row.expires };
  }

  saveRefreshToken(record: RefreshTokenRecord): void {
    this.db.prepare('INSERT INTO refresh_tokens (token, client_id, subject, scope, expires) VALUES (?, ?, ?, ?, ?)')
      .run(record.token, record.clientId, record.subject, record.scope, record.expires);
  }

  getRefreshToken(token: string): RefreshTokenRecord | undefined {
    const row = this.db.prepare('SELECT token, client_id, subject, scope, expires FROM refresh_tokens WHERE token = ?')
      .get(token) as {token:string;client_id:string;subject:string;scope:string;expires:number}|undefined;
    if (!row || row.expires < Date.now()) {
      if (row) this.db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(token);
      return undefined;
    }
    return { token: row.token, clientId: row.client_id, subject: row.subject, scope: row.scope, expires: row.expires };
  }
}

export class SqliteUserStore implements UserStore {
  constructor(private readonly db: DatabaseSync) {
    // Backfill only a keyed digest. The derived +agent address is never stored.
    const missing = this.db.prepare('SELECT id, email FROM users WHERE agent_recipient_hash IS NULL AND email IS NOT NULL').all() as Array<{id:string;email:string}>;
    for (const row of missing) {
      try { this.db.prepare('UPDATE users SET agent_recipient_hash = ? WHERE id = ?').run(recipientDigest(agentAddressFromAccountEmail(row.email)), row.id); }
      catch (error) { throw new Error('Could not derive agent recipient digest for an existing user. Check account email and AGENT_RECIPIENT_HMAC_SECRET.', { cause: error }); }
    }
  }

  createUser(user: McpUser): void {
    const digest = user.email ? recipientDigest(agentAddressFromAccountEmail(user.email)) : user.agentRecipientHash;
    this.db.prepare('INSERT INTO users (id, name, email, password_hash, created_at, last_tool_call_at, agent_recipient_hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(user.id, user.name, user.email ?? null, user.passwordHash ?? null, user.createdAt, user.lastToolCallAt ?? null, digest ?? null);
    const metricsTable = this.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'usage_totals'").get();
    if (metricsTable) this.db.prepare("UPDATE usage_totals SET value = value + 1 WHERE key = 'accounts_created'").run();
  }

  listUsers(): McpUser[] {
    const rows = this.db.prepare('SELECT id, name, email, password_hash, created_at, last_tool_call_at, agent_recipient_hash FROM users ORDER BY name, id').all() as Array<{id:string;name:string;email:string|null;password_hash:string|null;created_at:number;last_tool_call_at:number|null;agent_recipient_hash:string|null}>;
    return rows.map(row => ({ id: row.id, name: row.name, ...(row.email ? {email:row.email} : {}), ...(row.agent_recipient_hash ? {agentRecipientHash:row.agent_recipient_hash} : {}), ...(row.password_hash ? {passwordHash:row.password_hash} : {}), createdAt: row.created_at, ...(row.last_tool_call_at !== null ? { lastToolCallAt: row.last_tool_call_at } : {}) }));
  }

  getUser(id: string): McpUser | undefined {
    return this.map(this.db.prepare('SELECT id, name, email, password_hash, created_at, last_tool_call_at, agent_recipient_hash FROM users WHERE id = ?').get(id) as {id:string;name:string;email:string|null;password_hash:string|null;created_at:number;last_tool_call_at:number|null;agent_recipient_hash:string|null}|undefined);
  }

  getUserByEmail(email: string): McpUser | undefined {
    return this.map(this.db.prepare('SELECT id, name, email, password_hash, created_at, last_tool_call_at, agent_recipient_hash FROM users WHERE lower(email) = lower(?)').get(email) as {id:string;name:string;email:string|null;password_hash:string|null;created_at:number;last_tool_call_at:number|null;agent_recipient_hash:string|null}|undefined);
  }

  updateAgentRecipientHash(id: string, digest: string): McpUser | undefined {
    this.db.prepare('UPDATE users SET agent_recipient_hash = ? WHERE id = ?').run(digest, id);
    return this.getUser(id);
  }

  updateUser(id: string, patch: {name?:string;email?:string;passwordHash?:string}): McpUser | undefined {
    const current = this.getUser(id);
    if (!current) return undefined;
    const nextEmail = patch.email ?? current.email;
    const digest = nextEmail ? recipientDigest(agentAddressFromAccountEmail(nextEmail)) : current.agentRecipientHash ?? null;
    this.db.prepare('UPDATE users SET name = ?, email = ?, password_hash = ?, agent_recipient_hash = ? WHERE id = ?')
      .run(patch.name ?? current.name, nextEmail ?? null, patch.passwordHash ?? current.passwordHash ?? null, digest, id);
    return this.getUser(id);
  }

  deleteUser(id: string): boolean {
    const tableExists = (name: string) => Boolean(this.db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
    ).get(name));
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM authorization_codes WHERE subject = ?').run(id);
      this.db.prepare('DELETE FROM refresh_tokens WHERE subject = ?').run(id);
      if (tableExists('gmail_metadata_cache')) this.db.prepare('DELETE FROM gmail_metadata_cache WHERE user_id = ?').run(id);
      if (tableExists('google_credentials')) this.db.prepare('DELETE FROM google_credentials WHERE user_id = ?').run(id);
      const deleted = this.db.prepare('DELETE FROM users WHERE id = ?').run(id).changes > 0;
      this.db.exec('COMMIT');
      return deleted;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  recordToolCall(id: string): boolean {
    this.pruneInactiveUsers();
    return this.db.prepare('UPDATE users SET last_tool_call_at = ? WHERE id = ?').run(Date.now(), id).changes > 0;
  }

  pruneInactiveUsers(): number {
    const cutoff = Date.now() - 15 * 24 * 60 * 60 * 1000;
    const expired = this.db.prepare(
      'SELECT id FROM users WHERE COALESCE(last_tool_call_at, created_at) <= ?'
    ).all(cutoff) as Array<{ id: string }>;
    if (expired.length === 0) return 0;

    const tableExists = (name: string) => Boolean(this.db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
    ).get(name));
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const { id } of expired) {
        this.db.prepare('DELETE FROM authorization_codes WHERE subject = ?').run(id);
        this.db.prepare('DELETE FROM refresh_tokens WHERE subject = ?').run(id);
        if (tableExists('gmail_metadata_cache')) {
          this.db.prepare('DELETE FROM gmail_metadata_cache WHERE user_id = ?').run(id);
        }
        if (tableExists('google_credentials')) {
          this.db.prepare('DELETE FROM google_credentials WHERE user_id = ?').run(id);
        }
        this.db.prepare('DELETE FROM users WHERE id = ?').run(id);
      }
      this.db.exec('COMMIT');
      return expired.length;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  private map(row: {id:string;name:string;email:string|null;password_hash:string|null;created_at:number;last_tool_call_at:number|null;agent_recipient_hash:string|null}|undefined): McpUser|undefined {
    return row ? {id:row.id,name:row.name,...(row.email ? {email:row.email}:{}),...(row.agent_recipient_hash ? {agentRecipientHash:row.agent_recipient_hash}:{}),...(row.password_hash ? {passwordHash:row.password_hash}:{}),createdAt:row.created_at,...(row.last_tool_call_at !== null ? {lastToolCallAt:row.last_tool_call_at}: {})} : undefined;
  }
}
