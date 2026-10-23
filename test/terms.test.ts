import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { mountTermsPage } from '../src/terms.js';

describe('terms page', () => {
  it('serves a no-store terms page linked to the privacy notice', async () => {
    const app = Fastify();
    await mountTermsPage(app);
    const response = await app.inject({ method: 'GET', url: '/terms' });
    assert.equal(response.statusCode, 200);
    assert.match(response.headers['content-type'] ?? '', /text\/html/);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.match(response.body, /read-only access/);
    assert.match(response.body, /href="\/gdpr"/);
    await app.close();
  });
});
