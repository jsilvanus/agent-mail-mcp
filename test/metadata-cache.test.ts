import { DatabaseSync } from 'node:sqlite';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteMetadataCache } from '../src/storage/metadata-cache.js';

describe('SQLite Gmail metadata cache', () => {
  it('encrypts metadata, scopes entries to a user, and slides expiry on each hit', () => {
    const db = new DatabaseSync(':memory:');
    let now = 1_000;
    const cache = new SqliteMetadataCache(db, Buffer.alloc(32, 7), 100, () => now);
    const metadata = {
      id: 'gmail-message-1',
      threadId: 'thread-1',
      labelIds: ['INBOX'],
      payload: { headers: [{ name: 'From', value: 'secret-sender@example.com' }, { name: 'Subject', value: 'Sensitive subject' }] },
    };

    cache.set('user-a', 'gmail-message-1', metadata);
    assert.deepEqual(cache.get('user-a', 'gmail-message-1'), metadata);
    assert.equal(cache.get('user-b', 'gmail-message-1'), undefined);

    const stored = db.prepare('SELECT ciphertext, expires_at FROM gmail_metadata_cache WHERE user_id = ? AND message_id = ?')
      .get('user-a', 'gmail-message-1') as { ciphertext: string; expires_at: number };
    assert.equal(stored.expires_at, 1_100);
    assert.ok(!stored.ciphertext.includes('Sensitive subject'));
    assert.ok(!stored.ciphertext.includes('secret-sender@example.com'));

    now = 1_050;
    assert.deepEqual(cache.get('user-a', 'gmail-message-1'), metadata);
    const refreshed = db.prepare('SELECT expires_at FROM gmail_metadata_cache WHERE user_id = ? AND message_id = ?')
      .get('user-a', 'gmail-message-1') as { expires_at: number };
    assert.equal(refreshed.expires_at, 1_150);

    now = 1_149;
    assert.deepEqual(cache.get('user-a', 'gmail-message-1'), metadata);
    now = 1_250;
    assert.equal(cache.get('user-a', 'gmail-message-1'), undefined);
    assert.equal(cache.pruneExpired(), 0);
    db.close();
  });

  it('rejects a too-short root secret', () => {
    const db = new DatabaseSync(':memory:');
    assert.throws(() => new SqliteMetadataCache(db, Buffer.alloc(16)), /at least 32 bytes/);
    db.close();
  });
});
