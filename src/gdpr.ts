import type { FastifyInstance } from 'fastify';

export interface GdprConfig {
  controllerName: string;
  controllerAddress: string;
  controllerEmail: string;
  privacyContactEmail: string;
  purposes: string;
  lawfulBasis: string;
  retention: string;
  recipients: string;
  internationalTransfers: string;
  supervisoryAuthority: string;
  dpoContact?: string;
}

const REQUIRED_ENV: Array<[keyof Omit<GdprConfig, 'dpoContact'>, string]> = [
  ['controllerName', 'GDPR_CONTROLLER_NAME'],
  ['controllerAddress', 'GDPR_CONTROLLER_ADDRESS'],
  ['controllerEmail', 'GDPR_CONTROLLER_EMAIL'],
  ['privacyContactEmail', 'GDPR_PRIVACY_CONTACT_EMAIL'],
  ['purposes', 'GDPR_PURPOSES'],
  ['lawfulBasis', 'GDPR_LAWFUL_BASIS'],
  ['retention', 'GDPR_RETENTION'],
  ['recipients', 'GDPR_RECIPIENTS'],
  ['internationalTransfers', 'GDPR_INTERNATIONAL_TRANSFERS'],
  ['supervisoryAuthority', 'GDPR_SUPERVISORY_AUTHORITY'],
];

export function loadGdprConfig(env: NodeJS.ProcessEnv = process.env): GdprConfig {
  const missing = REQUIRED_ENV.filter(([, name]) => !env[name]?.trim()).map(([, name]) => name);
  if (missing.length) {
    throw new Error('Required GDPR notice environment variables are missing or blank: ' + missing.join(', '));
  }

  const values = Object.fromEntries(REQUIRED_ENV.map(([key, name]) => [key, env[name]!.trim()])) as Omit<GdprConfig, 'dpoContact'>;
  const dpoContact = env.GDPR_DPO_CONTACT?.trim();
  return { ...values, ...(dpoContact ? { dpoContact } : {}) };
}

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function mailto(value: string): string {
  return value.replaceAll('&', '%26').replaceAll('?', '%3F').replaceAll('#', '%23').replaceAll(' ', '%20');
}

function paragraphs(value: string): string {
  return value.split(/\r?\n\s*\r?\n/).map(part => '<p>' + escapeHtml(part).replaceAll('\n', '<br>') + '</p>').join('');
}

export async function mountGdprPage(app: FastifyInstance, config: GdprConfig): Promise<void> {
  app.get('/gdpr', async (_request, reply) => {
    const email = escapeHtml(config.privacyContactEmail);
    const subject = mailto('GDPR data deletion request');
    const body = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<meta name="robots" content="noindex,follow"><title>Privacy notice — Agent Mail MCP</title>' +
      '<style>body{font:16px/1.6 system-ui,sans-serif;color:#202124;background:#f7f8fa;margin:0;padding:2rem 1rem}' +
      'main{max-width:850px;margin:auto;background:white;padding:clamp(1.2rem,4vw,3rem);border-radius:12px}' +
      'h1,h2{line-height:1.2}h2{margin-top:2rem}a{color:#1459a6}li{margin:.35rem 0}.contact{padding:1rem;background:#f1f4f8;border-radius:8px}' +
      '.button{display:inline-block;padding:.75rem 1rem;background:#174ea6;color:white;text-decoration:none;border-radius:6px;font-weight:600}' +
      'small{color:#555}</style></head><body><main><h1>Privacy notice</h1>' +
      '<p>Agent Mail MCP is a read-only Model Context Protocol service that lets an authorised client list and retrieve messages addressed to a Gmail <code>+agent</code> alias.</p>' +
      '<p><small>This notice is generated from the service operator’s deployment configuration. The controller must ensure the configured legal details are accurate and current.</small></p>' +
      '<h2>1. Data controller and contact</h2><div class="contact"><p><strong>' + escapeHtml(config.controllerName) + '</strong></p>' +
      '<p>' + escapeHtml(config.controllerAddress).replaceAll('\n', '<br>') + '</p>' +
      '<p>Controller email: <a href="mailto:' + mailto(config.controllerEmail) + '">' + escapeHtml(config.controllerEmail) + '</a></p>' +
      '<p>Privacy requests: <a href="mailto:' + mailto(config.privacyContactEmail) + '">' + email + '</a></p>' +
      (config.dpoContact ? '<p>Data Protection Officer: ' + escapeHtml(config.dpoContact) + '</p>' : '') + '</div>' +
      '<h2>2. Purposes and lawful basis</h2>' + paragraphs(config.purposes) +
      '<p><strong>Lawful basis supplied by the controller:</strong> ' + escapeHtml(config.lawfulBasis) + '</p>' +
      '<h2>3. Personal data handled</h2><ul>' +
      '<li><strong>Service account and access data:</strong> internal account identifier, account name/email where configured, password hash for local accounts, and account creation/activity timestamps.</li>' +
      '<li><strong>MCP authorisation data:</strong> client identifiers, scopes, short-lived authorisation codes and refresh tokens needed to authorise MCP clients.</li>' +
      '<li><strong>Gmail data processed on request:</strong> message IDs, recipient/sender headers, subject, date, labels and spam-related headers are fetched to identify matching messages. Message headers and bodies are not persisted by the current connector. A message body is fetched only when the message tool is called and is returned to the authorised client.</li>' +
      '<li><strong>Operational data:</strong> the hosting environment and its logging configuration may process connection metadata such as IP address, request path, timestamps and error details. The operator must review and configure logs separately.</li>' +
      '</ul><p>The service currently uses Gmail credentials configured by the operator in environment variables. It does not yet link a separate Google identity to each local MCP account. Do not interpret this notice as saying the service stores per-user Google OAuth tokens.</p>' +
      '<h2>4. Recipients and service providers</h2>' + paragraphs(config.recipients) +
      '<h2>5. International transfers</h2>' + paragraphs(config.internationalTransfers) +
      '<h2>6. Retention</h2>' + paragraphs(config.retention) +
      '<p>The service removes inactive local user records after 15 days without an MCP tool call, including associated MCP authorisation codes and refresh tokens. The configured retention statement should also explain hosting logs, backups, and any provider-side retention.</p>' +
      '<h2>7. Your rights</h2><p>Subject to applicable law, you may request access, rectification, erasure, restriction, portability, or object to processing where those rights apply. You may also lodge a complaint with the supervisory authority listed below. Requests will be handled by the controller, who may need to verify your identity before disclosing or deleting data.</p>' +
      '<h2>8. Request deletion</h2><p>Use the contact link to request deletion. This currently opens an email request; it does not automatically delete data. Do not include your password, access token, refresh token, or message contents in the request.</p>' +
      '<p><a class="button" href="mailto:' + mailto(config.privacyContactEmail) + '?subject=' + subject + '">Request deletion of my data</a></p>' +
      '<p>A direct “delete my data” action verified through Google OAuth is not enabled yet. The current service has local MCP accounts and operator-configured shared Gmail credentials, so Google sign-in alone cannot safely identify which local records belong to the requester.</p>' +
      '<h2>9. Supervisory authority</h2>' + paragraphs(config.supervisoryAuthority) +
      '<h2>10. Changes</h2><p>This notice may be updated when the service or its data handling changes. The controller is responsible for ensuring that this notice reflects actual deployment practices and applicable law.</p>' +
      '<p><a href="/">Back to service</a></p></main></body></html>';
    return reply.header('Cache-Control', 'no-store').header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'").type('text/html; charset=utf-8').send(body);
  });
}
