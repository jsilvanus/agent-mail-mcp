import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { SqliteMetadataCache } from '../src/storage/metadata-cache.js';

const DAY = 24 * 60 * 60 * 1000;

describe('15-day user inactivity TTL', () => {
  it('expires users after 15 days without a tool call and removes their stored state', () => {
    const auth = new SqliteAuthStore(':memory:');
    const db = auth.getDatabase();
    const users = new SqliteUserStore(db);
    const cache = new SqliteMetadataCache(db, Buffer.alloc(32, 7));
    const now = Date.now();

    users.createUser({ id: 'inactive', name: 'Inactive', createdAt: now - 16 * DAY });
    users.createUser({ id: 'active', name: 'Active', createdAt: now - 30 * DAY, lastToolCallAt: now - DAY });
    auth.saveAuthorizationCode({
      code: 'inactive-code', clientId: 'client', redirectUri: 'https://client.example/callback',
      challenge: 'challenge', subject: 'inactive', scope: 'mcp', expires: now + DAY,
    });
    auth.saveRefreshToken({
      token: 'inactive-refresh', clientId: 'client', subject: 'inactive', scope: 'mcp', expires: now + DAY,
    });
    cache.set('inactive', 'message-1', { id: 'message-1', labelIds: ['INBOX'] });

    assert.equal(users.pruneInactiveUsers(), 1);
    assert.equal(users.getUser('inactive'), undefined);
    assert.equal(users.getUser('active')?.id, 'active');
    assert.equal(auth.getRefreshToken('inactive-refresh'), undefined);
    assert.equal(auth.consumeAuthorizationCode('inactive-code'), undefined);
    assert.equal(cache.get('inactive', 'message-1'), undefined);

    db.close();
  });

  it('refreshes the inactivity timestamp on a tool call', () => {
    const auth = new SqliteAuthStore(':memory:');
    const db = auth.getDatabase();
    const users = new SqliteUserStore(db);
    const now = Date.now();
    users.createUser({ id: 'recent-call', name: 'Recent', createdAt: now - 14 * DAY });

    assert.equal(users.recordToolCall('recent-call'), true);
    const user = users.getUser('recent-call');
    assert.ok(user?.lastToolCallAt);
    assert.ok(user.lastToolCallAt >= now);
    assert.equal(users.pruneInactiveUsers(), 0);

    db.close();
  });

  it('rejects and removes a user whose last tool call was over 15 days ago', () => {
    const auth = new SqliteAuthStore(':memory:');
    const db = auth.getDatabase();
    const users = new SqliteUserStore(db);
    const now = Date.now();
    users.createUser({ id: 'stale', name: 'Stale', createdAt: now - 40 * DAY, lastToolCallAt: now - 16 * DAY });

    assert.equal(users.recordToolCall('stale'), false);
    assert.equal(users.getUser('stale'), undefined);
    db.close();
  });
});
