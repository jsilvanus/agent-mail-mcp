import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SqliteUsageMetrics } from '../src/storage/usage-metrics.js';

describe('pseudonymous usage metrics', () => {
  it('counts endpoint calls per pseudonymous user without storing raw user IDs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agent-mail-metrics-'));
    const db = new DatabaseSync(join(dir, 'metrics.sqlite'));
    try {
      const metrics = new SqliteUsageMetrics(db, Buffer.from('metrics-secret-which-is-at-least-32-bytes'));
      metrics.recordCall('account-one', 'agent_inbox_list', 100);
      metrics.recordCall('account-one', 'agent_inbox_list', 200);
      metrics.recordCall('account-one', 'agent_inbox_message', 300);
      metrics.recordCall('account-two', 'agent_inbox_list', 400);
      const snapshot = metrics.snapshot(2);
      assert.equal(snapshot.currentUsers, 2);
      assert.deepEqual(snapshot.callsByEndpoint, [
        { endpoint: 'agent_inbox_list', calls: 3 },
        { endpoint: 'agent_inbox_message', calls: 1 },
      ]);
      assert.equal(snapshot.users.length, 3);
      assert.ok(snapshot.users.every(row => row.user !== 'account-one' && row.user !== 'account-two'));
      assert.equal(snapshot.users.find(row => row.endpoint === 'agent_inbox_list' && row.lastCalledAt === 200)?.calls, 2);
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('requires a 32-byte metrics key', () => {
    const db = new DatabaseSync(':memory:');
    try { assert.throws(() => new SqliteUsageMetrics(db, Buffer.from('short')), /at least 32 bytes/); }
    finally { db.close(); }
  });
});
