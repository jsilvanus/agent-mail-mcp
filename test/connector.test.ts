import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { GmailConnector } from '../src/connector.js';

describe('Gmail agent inbox filtering', () => {
  it('lists only exact +agent recipients and refuses unrelated message IDs', async () => {
    const previousFetch = globalThis.fetch;
    const previousToken = process.env.GMAIL_ACCESS_TOKEN;
    process.env.GMAIL_ACCESS_TOKEN = 'test-token';

    const data: Record<string, unknown> = {
      target: {
        id: 'target', internalDate: '1790000000000',
        payload: { headers: [
          { name: 'To', value: 'someone+agent@gmail.com' },
          { name: 'From', value: 'sender@example.net' },
          { name: 'Subject', value: 'Agent task' },
          { name: 'Date', value: 'Thu, 22 Oct 2026 12:00:00 +0000' },
        ] },
      },
      regular: {
        id: 'regular', payload: { headers: [
          { name: 'To', value: 'someone@gmail.com' },
          { name: 'From', value: 'sender@example.net' },
          { name: 'Subject', value: 'Regular mail' },
        ] },
      },
    };

    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = new URL(typeof input === 'string' || input instanceof URL ? input.toString() : input.url);
      if (url.pathname.endsWith('/messages') && !url.pathname.match(/\/messages\/[^/]+$/)) {
        return Response.json({ messages: [{ id: 'target' }, { id: 'regular' }], resultSizeEstimate: 2 });
      }
      const id = url.pathname.split('/').pop()!;
      const message = data[id];
      if (!message) return new Response('not found', { status: 404 });
      const value = structuredClone(message) as Record<string, unknown>;
      if (url.searchParams.get('format') === 'full' && id === 'target') {
        value.snippet = 'Hello agent';
        value.payload = {
          ...(value.payload as object),
          mimeType: 'text/plain',
          body: { data: Buffer.from('Hello agent').toString('base64url') },
        };
      }
      return Response.json(value);
    }) as typeof fetch;

    try {
      const connector = new GmailConnector();
      const result = await connector.search({ pageSize: 50 }, {});
      assert.deepEqual((result as { messages: Array<{ id: string; subject: string }> }).messages, [
        { id: 'target', time: 'Thu, 22 Oct 2026 12:00:00 +0000', sender: 'sender@example.net', subject: 'Agent task' },
      ]);
      assert.equal(await connector.get('target', {}).then(x => (x as { body: string }).body), 'Hello agent');
      await assert.rejects(connector.get('regular', {}), /not found in the \+agent inbox/);
    } finally {
      globalThis.fetch = previousFetch;
      if (previousToken === undefined) delete process.env.GMAIL_ACCESS_TOKEN;
      else process.env.GMAIL_ACCESS_TOKEN = previousToken;
    }
  });
});
