import { createHmac } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

export interface UsageMetricRow {
  user: string;
  endpoint: string;
  calls: number;
  lastCalledAt: number;
}

/**
 * Minimal usage counters. Raw account IDs, email addresses, message IDs, arguments,
 * and message content are never written to this metrics table.
 */
export class SqliteUsageMetrics {
  constructor(private readonly db: DatabaseSync, private readonly secret: Uint8Array) {
    if (secret.byteLength < 32) throw new Error('METRICS_HMAC_SECRET must contain at least 32 bytes.');
    db.exec(
      'CREATE TABLE IF NOT EXISTS usage_metrics (' +
      'user_key TEXT NOT NULL, endpoint TEXT NOT NULL, calls INTEGER NOT NULL DEFAULT 0, ' +
      'last_called_at INTEGER NOT NULL, PRIMARY KEY (user_key, endpoint))'
    );
    db.exec('CREATE TABLE IF NOT EXISTS usage_totals (key TEXT PRIMARY KEY, value INTEGER NOT NULL)');
    db.prepare("INSERT OR IGNORE INTO usage_totals (key, value) VALUES ('accounts_created', 0)").run();
  }

  private userKey(userId: string): string {
    return createHmac('sha256', this.secret).update('agent-mail-mcp:metrics:v1\0').update(userId).digest('hex');
  }

  accountCreated(): void {
    this.db.prepare("UPDATE usage_totals SET value = value + 1 WHERE key = 'accounts_created'").run();
  }

  recordCall(userId: string, endpoint: string, at = Date.now()): void {
    const key = this.userKey(userId);
    this.db.prepare(
      'INSERT INTO usage_metrics (user_key, endpoint, calls, last_called_at) VALUES (?, ?, 1, ?) ' +
      'ON CONFLICT(user_key, endpoint) DO UPDATE SET calls = calls + 1, last_called_at = excluded.last_called_at'
    ).run(key, endpoint, at);
  }

  snapshot(currentUsers: number): { currentUsers: number; accountsCreated: number; callsByEndpoint: Array<{endpoint:string;calls:number}>; users: UsageMetricRow[] } {
    const total = this.db.prepare("SELECT value FROM usage_totals WHERE key = 'accounts_created'").get() as {value:number}|undefined;
    const endpoints = this.db.prepare('SELECT endpoint, SUM(calls) AS calls FROM usage_metrics GROUP BY endpoint ORDER BY endpoint').all() as Array<{endpoint:string;calls:number}>;
    const users = this.db.prepare('SELECT user_key, endpoint, calls, last_called_at FROM usage_metrics ORDER BY user_key, endpoint').all() as Array<{user_key:string;endpoint:string;calls:number;last_called_at:number}>;
    return {
      currentUsers,
      accountsCreated: total?.value ?? 0,
      callsByEndpoint: endpoints.map(row => ({ endpoint: row.endpoint, calls: row.calls })),
      users: users.map(row => ({ user: row.user_key, endpoint: row.endpoint, calls: row.calls, lastCalledAt: row.last_called_at })),
    };
  }

  pruneUsers(userIds: string[]): void {
    const remove = this.db.prepare('DELETE FROM usage_metrics WHERE user_key = ?');
    for (const id of userIds) remove.run(this.userKey(id));
  }
}
