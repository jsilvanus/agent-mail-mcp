import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

export interface GmailMetadata {
  id?: string;
  threadId?: string;
  internalDate?: string;
  labelIds?: string[];
  payload?: {
    headers?: Array<{ name?: string; value?: string }>;
  };
}

export interface MetadataCache<T> {
  get(userId: string, messageId: string): T | undefined;
  set(userId: string, messageId: string, value: T): void;
}

const EIGHT_DAYS_MS = 8 * 24 * 60 * 60 * 1000;

/**
 * Encrypted, user-partitioned Gmail metadata cache.
 *
 * The root secret is never used directly as an AES key: each OAuth user gets a
 * separate key via HMAC-based derivation, and AES-GCM AAD binds ciphertext to
 * both that user and message ID. A successful read slides the expiry forward
 * by eight days.
 */
export class SqliteMetadataCache implements MetadataCache<GmailMetadata> {
  constructor(
    private readonly db: DatabaseSync,
    private readonly rootSecret: Uint8Array,
    private readonly ttlMs = EIGHT_DAYS_MS,
    private readonly now: () => number = Date.now,
  ) {
    if (rootSecret.byteLength < 32) throw new Error('Metadata cache root secret must be at least 32 bytes.');
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS gmail_metadata_cache (' +
      'user_id TEXT NOT NULL, message_id TEXT NOT NULL, iv TEXT NOT NULL, auth_tag TEXT NOT NULL, ciphertext TEXT NOT NULL, ' +
      'last_hit_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (user_id, message_id))'
    );
    this.db.exec('CREATE INDEX IF NOT EXISTS gmail_metadata_cache_expiry ON gmail_metadata_cache (expires_at)');
  }

  private keyFor(userId: string): Buffer {
    return createHmac('sha256', this.rootSecret)
      .update('agent-mail-mcp:gmail-metadata-cache:v1\\0', 'utf8')
      .update(userId, 'utf8')
      .digest();
  }

  private aad(userId: string, messageId: string): Buffer {
    return Buffer.from('agent-mail-mcp:gmail-metadata-cache:v1\\0' + userId + '\\0' + messageId, 'utf8');
  }

  get(userId: string, messageId: string): GmailMetadata | undefined {
    if (!userId || !messageId) return undefined;
    const row = this.db.prepare(
      'SELECT iv, auth_tag, ciphertext, expires_at FROM gmail_metadata_cache WHERE user_id = ? AND message_id = ?'
    ).get(userId, messageId) as { iv: string; auth_tag: string; ciphertext: string; expires_at: number } | undefined;
    if (!row) return undefined;

    const now = this.now();
    if (row.expires_at <= now) {
      this.db.prepare('DELETE FROM gmail_metadata_cache WHERE user_id = ? AND message_id = ?').run(userId, messageId);
      return undefined;
    }

    try {
      const decipher = createDecipheriv('aes-256-gcm', this.keyFor(userId), Buffer.from(row.iv, 'base64url'));
      decipher.setAAD(this.aad(userId, messageId));
      decipher.setAuthTag(Buffer.from(row.auth_tag, 'base64url'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(row.ciphertext, 'base64url')),
        decipher.final(),
      ]).toString('utf8');
      const value = JSON.parse(plaintext) as GmailMetadata;
      this.db.prepare('UPDATE gmail_metadata_cache SET last_hit_at = ?, expires_at = ? WHERE user_id = ? AND message_id = ?')
        .run(now, now + this.ttlMs, userId, messageId);
      return value;
    } catch {
      // Corrupt, tampered, or undecryptable entries are discarded and fetched again.
      this.db.prepare('DELETE FROM gmail_metadata_cache WHERE user_id = ? AND message_id = ?').run(userId, messageId);
      return undefined;
    }
  }

  set(userId: string, messageId: string, value: GmailMetadata): void {
    if (!userId || !messageId) return;
    const now = this.now();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.keyFor(userId), iv);
    cipher.setAAD(this.aad(userId, messageId));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    this.db.prepare(
      'INSERT INTO gmail_metadata_cache (user_id, message_id, iv, auth_tag, ciphertext, last_hit_at, expires_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id, message_id) DO UPDATE SET ' +
      'iv = excluded.iv, auth_tag = excluded.auth_tag, ciphertext = excluded.ciphertext, ' +
      'last_hit_at = excluded.last_hit_at, expires_at = excluded.expires_at'
    ).run(
      userId, messageId, iv.toString('base64url'), cipher.getAuthTag().toString('base64url'),
      ciphertext.toString('base64url'), now, now + this.ttlMs,
    );
  }

  /** Remove expired entries opportunistically; safe to call at startup or after a list. */
  pruneExpired(): number {
    return Number(this.db.prepare('DELETE FROM gmail_metadata_cache WHERE expires_at <= ?').run(this.now()).changes);
  }
}
