import type { FastifyInstance } from 'fastify';

export interface GdprConfig {
  controllerName: string;
  controllerAddress: string;
  controllerEmail: string;
  privacyContactEmail: string;
  hostingCountry: string;
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
  ['hostingCountry', 'SERVICE_HOSTING_COUNTRY'],
  ['purposes', 'GDPR_PURPOSES'],
  ['lawfulBasis', 'GDPR_LAWFUL_BASIS'],
  ['retention', 'GDPR_RETENTION'],
  ['recipients', 'GDPR_RECIPIENTS'],
  ['internationalTransfers', 'GDPR_INTERNATIONAL_TRANSFERS'],
  ['supervisoryAuthority', 'GDPR_SUPERVISORY_AUTHORITY'],
];

export function loadGdprConfig(env: NodeJS.ProcessEnv = process.env): GdprConfig {
  const missing = REQUIRED_ENV.filter(([, name]) => !env[name]?.trim()).map(([, name]) => name);
  if (missing.length) throw new Error('Required privacy notice environment variables are missing or blank: ' + missing.join(', '));
  const values = Object.fromEntries(REQUIRED_ENV.map(([key, name]) => [key, env[name]!.trim()])) as Omit<GdprConfig, 'dpoContact'>;
  const dpoContact = env.GDPR_DPO_CONTACT?.trim();
  return { ...values, ...(dpoContact ? { dpoContact } : {}) };
}

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
function mailto(value: string): string { return encodeURIComponent(value).replaceAll('%40', '@').replaceAll('%2E', '.'); }
function paragraphs(value: string): string {
  return value.split(/\r?\n\s*\r?\n/).map(part => '<p>' + escapeHtml(part).replaceAll('\n', '<br>') + '</p>').join('');
}

export async function mountGdprPage(app: FastifyInstance, config: GdprConfig): Promise<void> {
  app.get('/privacy', async (_request, reply) => reply.code(308).header('Cache-Control', 'no-store').redirect('/gdpr'));
  app.get('/gdpr', async (_request, reply) => {
    const email = escapeHtml(config.privacyContactEmail);
    const subject = encodeURIComponent('GDPR data request');
    const body = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,follow">' +
      '<title>Privacy notice — Agent Mail MCP</title>' +
      '<style>body{font:16px/1.65 system-ui,sans-serif;color:#202124;background:#f7f8fa;margin:0;padding:2rem 1rem}main{max-width:900px;margin:auto;background:white;padding:clamp(1.2rem,4vw,3rem);border-radius:12px}h1,h2{line-height:1.2}h2{margin-top:2rem}a{color:#1459a6}li{margin:.4rem 0}.contact{padding:1rem;background:#f1f4f8;border-radius:8px}.button{display:inline-block;padding:.75rem 1rem;background:#174ea6;color:white;text-decoration:none;border-radius:6px;font-weight:600}small{color:#555}</style></head><body><main>' +
      '<h1>Privacy notice</h1>' +
      '<p>Agent Mail MCP is a read-only Model Context Protocol (MCP) service. It routes email addressed to a user-specific Gmail <code>+agent</code> address from Gmail to the AI service that the user has configured. It does not compose, send, or modify email.</p>' +
      '<p><small>This notice is generated from deployment configuration. The controller must keep the configuration accurate and ensure the actual processing and provider contracts match this description.</small></p>' +
      '<h2>1. Controller and contact</h2><div class="contact"><p><strong>' + escapeHtml(config.controllerName) + '</strong></p><p>' + escapeHtml(config.controllerAddress).replaceAll('\n','<br>') + '</p><p>Controller: <a href="mailto:' + mailto(config.controllerEmail) + '">' + escapeHtml(config.controllerEmail) + '</a></p><p>Privacy requests: <a href="mailto:' + mailto(config.privacyContactEmail) + '">' + email + '</a></p>' +
      (config.dpoContact ? '<p>Data Protection Officer: ' + escapeHtml(config.dpoContact) + '</p>' : '') + '</div>' +
      '<h2>2. Purposes</h2>' + paragraphs(config.purposes) +
      '<p><strong>Lawful basis configured by the controller:</strong> ' + escapeHtml(config.lawfulBasis) + '</p>' +
      '<h2>3. Data processed and how it flows</h2><ol>' +
      '<li><strong>Local account and Gmail access:</strong> this version uses an operator-created local MCP account and operator-configured shared Gmail OAuth credentials. Google sign-in and per-user Gmail OAuth onboarding are not implemented in this version. The service uses the local account email to derive the agent recipient and stores a keyed HMAC digest of that recipient.</li>' +
      '<li><strong>Recipient identity:</strong> the service derives the <code>username+agent@gmail.com</code> recipient and stores only a keyed HMAC digest. During discovery it reads candidate Gmail <code>To</code> headers in small batches, compares digests, then queries Gmail for that alias. The discovered address is held temporarily in server memory.</li>' +
      '<li><strong>Message listing:</strong> Gmail message IDs and metadata such as sender, recipient, subject, date, labels, and available spam headers are fetched on request. The service filters each message against the stored digest. It does not persist message headers, subjects, sender addresses, or bodies in its database.</li>' +
      '<li><strong>Message retrieval:</strong> when the authorised AI client requests a message, the service fetches the body from Gmail, verifies the recipient again, and returns the content to that MCP client. The AI provider may process or retain the returned content under its own terms and settings.</li>' +
      '<li><strong>Account and authorisation records:</strong> the service stores the local account identifier and email, the recipient HMAC digest, the password hash, creation/activity timestamps, MCP authorisation codes, and MCP refresh tokens. Short-lived codes are consumed at exchange. Access tokens and message content should not be written to application logs.</li>' +
      '<li><strong>Operational data:</strong> the host, reverse proxy, and monitoring/logging configuration may process IP addresses, request paths, timestamps, and error details. Their actual retention depends on deployment configuration.</li>' +
      '</ol><p>Data travels from Google/Gmail infrastructure, which may process data in multiple countries, through this service hosted in <strong>' + escapeHtml(config.hostingCountry) + '</strong>, to the AI service selected and configured by the user. The destination country is therefore user- and provider-dependent, not a single deployment setting; it may not be visible to this service. The user’s AI provider can receive personal data contained in email headers and bodies. Users should check their chosen AI provider’s processing locations, retention settings, and terms before enabling this routing.</p>' +
      '<h2>4. Recipients and providers</h2>' + paragraphs(config.recipients) +
      '<h2>5. International transfers</h2>' + paragraphs(config.internationalTransfers) +
      '<p>Google, the hosting provider, and the configured AI service may process data outside the European Economic Area. The applicable transfer mechanism and safeguards depend on the providers, their locations, and the user’s configuration; the controller must verify and document these for the deployment. This notice does not claim that a particular transfer safeguard applies unless the controller has confirmed it.</p>' +
      '<h2>6. Retention</h2>' + paragraphs(config.retention) +
      '<p>Local MCP account records are deleted after 15 consecutive days without a successful MCP tool call. Associated MCP authorisation codes and refresh tokens are deleted with the account. Message headers and bodies are not persisted by the connector. The matching alias is cached in process memory for up to five minutes. Google, the AI provider, and infrastructure logs may have separate retention periods under their own settings and terms.</p>' +
      '<h2>7. Your rights</h2><p>Depending on applicable law, you may request access, rectification, erasure, restriction, portability, or object to processing. You may complain to the supervisory authority below. The controller may need to verify your identity before responding.</p>' +
      '<h2>8. Delete my account and service data</h2><p>This version does not provide automated Google-verified account deletion. To request deletion, contact the privacy contact above and provide enough information for the operator to verify and locate the account. The operator can remove the local account and associated MCP authorisation records. This cannot delete messages from Gmail or erase copies already delivered to an AI provider, nor does it immediately remove infrastructure backups or provider logs.</p>' +
      '<p><a href="/terms">Read the service terms</a></p>' +
      '<p>If automated deletion is unavailable, contact <a href="mailto:' + mailto(config.privacyContactEmail) + '">' + email + '</a>. Do not send passwords, OAuth tokens, or email contents.</p>' +
      '<h2>9. Supervisory authority</h2>' + paragraphs(config.supervisoryAuthority) +
      '<h2>10. Changes</h2><p>This notice is updated when processing changes. The controller is responsible for keeping it accurate.</p><p><a href="/">Back to service</a></p></main></body></html>';
    return reply.header('Cache-Control', 'no-store').header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'").type('text/html; charset=utf-8').send(body);
  });
}
