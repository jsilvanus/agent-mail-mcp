import { createHmac, timingSafeEqual } from 'node:crypto';

/** The address itself is never persisted; only this keyed digest is stored per user. */
export function normalizeAddress(address: string): string {
  return address.trim().replace(/^<|>$/g, '').toLowerCase();
}

export function agentAddressFromAccountEmail(email: string): string {
  const value = email.trim().toLowerCase();
  const at = value.lastIndexOf('@');
  if (at <= 0 || at === value.length - 1) throw new Error('A valid account email is required to derive the +agent recipient.');
  const local = value.slice(0, at).split('+')[0];
  if (!/^[a-z0-9.]+$/.test(local)) throw new Error('Account email local part cannot be used as a Gmail +agent username.');
  return local + '+agent@gmail.com';
}

export function recipientDigest(address: string, secret = process.env.AGENT_RECIPIENT_HMAC_SECRET): string {
  if (!secret || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('AGENT_RECIPIENT_HMAC_SECRET must be configured with at least 32 UTF-8 bytes.');
  }
  return createHmac('sha256', secret).update(normalizeAddress(address), 'utf8').digest('hex');
}

export function recipientDigestMatches(address: string, expectedDigest: string, secret = process.env.AGENT_RECIPIENT_HMAC_SECRET): boolean {
  const actual = Buffer.from(recipientDigest(address, secret), 'hex');
  const expected = Buffer.from(expectedDigest, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function validateRecipientSecret(secret = process.env.AGENT_RECIPIENT_HMAC_SECRET): void {
  if (!secret || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('AGENT_RECIPIENT_HMAC_SECRET is required and must contain at least 32 UTF-8 bytes.');
  }
}
