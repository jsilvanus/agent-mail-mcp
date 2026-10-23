import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteAuthStore, SqliteUserStore } from '../src/storage/sqlite.js';
import { agentAddressFromAccountEmail, recipientDigest } from '../src/recipient-hmac.js';

describe('recipient HMAC storage', () => {
  it('stores only the keyed digest for the derived +agent address', () => {
    const previousSecret = process.env.AGENT_RECIPIENT_HMAC_SECRET;
    process.env.AGENT_RECIPIENT_HMAC_SECRET = 'test-recipient-hmac-secret-32-bytes-minimum';
    const auth = new SqliteAuthStore(':memory:');
    const db = auth.getDatabase();
    try {
      const users = new SqliteUserStore(db);
      users.createUser({ id: 'u1', name: 'Test', email: 'someone@example.net', createdAt: Date.now() });
      const alias = agentAddressFromAccountEmail('someone@example.net');
      const stored = db.prepare('SELECT agent_recipient_hash FROM users WHERE id = ?').get('u1') as { agent_recipient_hash: string };
      assert.equal(alias, 'someone+agent@gmail.com');
      assert.equal(stored.agent_recipient_hash, recipientDigest(alias));
      assert.notEqual(stored.agent_recipient_hash, alias);
      assert.equal(stored.agent_recipient_hash.length, 64);
      assert.equal(users.getUser('u1')?.agentRecipientHash, stored.agent_recipient_hash);
    } finally {
      db.close();
      if (previousSecret === undefined) delete process.env.AGENT_RECIPIENT_HMAC_SECRET;
      else process.env.AGENT_RECIPIENT_HMAC_SECRET = previousSecret;
    }
  });

  it('normalizes address case before hashing', () => {
    const previousSecret = process.env.AGENT_RECIPIENT_HMAC_SECRET;
    process.env.AGENT_RECIPIENT_HMAC_SECRET = 'test-recipient-hmac-secret-32-bytes-minimum';
    try {
      assert.equal(recipientDigest('Someone+Agent@Gmail.com'), recipientDigest('someone+agent@gmail.com'));
    } finally {
      if (previousSecret === undefined) delete process.env.AGENT_RECIPIENT_HMAC_SECRET;
      else process.env.AGENT_RECIPIENT_HMAC_SECRET = previousSecret;
    }
  });
});
