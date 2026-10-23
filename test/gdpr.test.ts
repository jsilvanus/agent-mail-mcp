import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { loadGdprConfig, mountGdprPage } from '../src/gdpr.js';

const required = {
  GDPR_CONTROLLER_NAME: 'Example Controller',
  GDPR_CONTROLLER_ADDRESS: '1 Example Street',
  GDPR_CONTROLLER_EMAIL: 'controller@example.test',
  GDPR_PRIVACY_CONTACT_EMAIL: 'privacy@example.test',
  GDPR_PURPOSES: 'Operate the read-only email connector.',
  GDPR_LAWFUL_BASIS: 'To be confirmed by the controller',
  GDPR_RETENTION: 'Inactive local accounts are removed after 15 days.',
  GDPR_RECIPIENTS: 'Hosting provider and Google APIs as configured.',
  GDPR_INTERNATIONAL_TRANSFERS: 'To be completed by the controller.',
  GDPR_SUPERVISORY_AUTHORITY: 'Relevant national authority',
};

describe('GDPR privacy page', () => {
  it('rejects startup configuration with missing required notice fields', () => {
    assert.throws(() => loadGdprConfig({}), /GDPR_CONTROLLER_NAME/);
  });

  it('renders controller contact, processing details and deletion request link', async () => {
    const config = loadGdprConfig(required);
    const app = Fastify();
    await mountGdprPage(app, config);
    const response = await app.inject({ method: 'GET', url: '/gdpr' });
    assert.equal(response.statusCode, 200);
    assert.match(response.headers['content-type'] ?? '', /text\/html/);
    assert.match(response.body, /Example Controller/);
    assert.match(response.body, /privacy@example\.test/);
    assert.match(response.body, /does not provide automated Google-verified account deletion/);
    assert.match(response.body, /\/terms/);
    await app.close();
  });
});
