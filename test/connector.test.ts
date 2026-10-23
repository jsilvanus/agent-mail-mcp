import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { GmailConnector } from '../src/connector.js';

type MockMessage = {
  id: string;
  threadId: string;
  internalDate?: string;
  snippet?: string;
  labelIds?: string[];
  payload: {
    mimeType?: string;
    headers: Array<{ name: string; value: string }>;
    body?: { data?: string };
    parts?: Array<{
      mimeType: string;
      body?: { data?: string };
      parts?: Array<unknown>;
    }>;
  };
};

const agentMessage: MockMessage = {
  id: 'agent-message-1',
  threadId: 'thread-1',
  internalDate: '1792670400000',
  snippet: 'Hello agent',
  labelIds: ['SPAM'],
  payload: {
    mimeType: 'text/plain',
    headers: [
      { name: 'To', value: 'A User <someone+agent@gmail.com>' },
      { name: 'From', value: 'sender@example.net' },
      { name: 'Subject', value: 'Agent task' },
      { name: 'Date', value: 'Thu, 22 Oct 2026 12:00:00 +0000' },
      { name: 'X-Spam-Status', value: 'Yes, score=7.2' },
    ],
    body: { data: Buffer.from('Hello agent').toString('base64url') },
  },
};

const ordinaryMessage: MockMessage = {
  id: 'ordinary-message-1',
  threadId: 'thread-2',
  internalDate: '1792670300000',
  payload: {
    mimeType: 'text/plain',
    headers: [
      { name: 'To', value: 'someone@gmail.com' },
      { name: 'From', value: 'sender@example.net' },
      { name: 'Subject', value: 'Regular mail' },
      { name: 'Date', value: 'Wed, 22 Oct 2026 11:58:20 +0000' },
    ],
    body: { data: Buffer.from('Not an agent message').toString('base64url') },
  },
};

function makeGmailMock(messages: MockMessage[]) {
  const requests: Array<{ url: URL; authorization: string | null }> = [];
  const byId = new Map(messages.map(message => [message.id, message]));
  const fetchMock = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input.toString() : input.url);
    const authorization = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).get('authorization');
    requests.push({ url, authorization });

    if (url.origin !== 'https://gmail.googleapis.com') return Response.json({ error: 'unexpected host' }, { status: 500 });
    if (authorization !== 'Bearer test-token') return Response.json({ error: { code: 401, message: 'Invalid Credentials' } }, { status: 401 });

    if (url.pathname === '/gmail/v1/users/me/messages') {
      assert.equal(url.searchParams.get('q'), 'in:anywhere');
      assert.equal(url.searchParams.get('includeSpamTrash'), 'true');
      const pageToken = url.searchParams.get('pageToken');
      if (pageToken === 'page-2') {
        return Response.json({ messages: [{ id: ordinaryMessage.id, threadId: ordinaryMessage.threadId }], resultSizeEstimate: 2 });
      }
      return Response.json({
        messages: [
          { id: agentMessage.id, threadId: agentMessage.threadId },
          { id: ordinaryMessage.id, threadId: ordinaryMessage.threadId },
        ],
        nextPageToken: 'page-2',
        resultSizeEstimate: 2,
      });
    }

    const match = url.pathname.match(/^\/gmail\/v1\/users\/me\/messages\/([^/]+)$/);
    if (!match) return Response.json({ error: { code: 404, message: 'Not Found' } }, { status: 404 });
    const id = decodeURIComponent(match[1]!);
    const message = byId.get(id);
    if (!message) return Response.json({ error: { code: 404, message: 'Not Found' } }, { status: 404 });

    const format = url.searchParams.get('format');
    if (format === 'metadata') {
      assert.deepEqual(url.searchParams.getAll('metadataHeaders'), [
        'To', 'Cc', 'Bcc', 'Delivered-To', 'X-Original-To', 'From', 'Subject', 'Date',
        'X-Spam-Status', 'X-Spam-Flag', 'X-Google-Spam', 'X-Gm-Spam',
      ]);
      const requested = new Set(url.searchParams.getAll('metadataHeaders').map(value => value.toLowerCase()));
      return Response.json({
        id: message.id,
        threadId: message.threadId,
        labelIds: message.labelIds ?? ['INBOX'],
        payload: {
          headers: message.payload.headers.filter(header => requested.has(header.name.toLowerCase())),
        },
      });
    }
    if (format === 'full') {
      return Response.json({
        id: message.id,
        threadId: message.threadId,
        internalDate: message.internalDate,
        snippet: message.snippet ?? '',
        payload: message.payload,
      });
    }
    return Response.json({ error: { code: 400, message: 'Unsupported format' } }, { status: 400 });
  };
  return { fetchMock, requests };
}

describe('Gmail API mock follows Google REST response shapes', () => {
  it('lists only exact +agent recipients, uses metadata format, and returns the Gmail page token', async () => {
    const previousFetch = globalThis.fetch;
    const previousToken = process.env.GMAIL_ACCESS_TOKEN;
    process.env.GMAIL_ACCESS_TOKEN = 'test-token';
    const mock = makeGmailMock([agentMessage, ordinaryMessage]);
    globalThis.fetch = mock.fetchMock as typeof fetch;

    try {
      const connector = new GmailConnector();
      const result = await connector.search({ pageSize: 50 }, {}) as {
        messages: Array<{ id: string; time: string; sender: string; subject: string }>;
        nextPageToken: string | null;
        resultSizeEstimate: number;
      };
      assert.deepEqual(result.messages, [{
        id: agentMessage.id,
        time: 'Wed, 22 Oct 2026 12:00:00 +0000',
        sender: 'sender@example.net',
        subject: 'Agent task',
        spamStatus: 'marked_spam',
        spamHints: {
          gmailSpamLabel: true,
          gmailLabels: ['SPAM'],
          headers: [{ name: 'x-spam-status', value: 'Yes, score=7.2' }],
        },
      }]);
      assert.equal(result.nextPageToken, 'page-2');
      assert.equal(result.resultSizeEstimate, 2);
      assert.equal(mock.requests.filter(request => request.url.searchParams.get('format') === 'metadata').length, 2);
      assert.ok(mock.requests.every(request => request.authorization === 'Bearer test-token'));
    } finally {
      globalThis.fetch = previousFetch;
      if (previousToken === undefined) delete process.env.GMAIL_ACCESS_TOKEN;
      else process.env.GMAIL_ACCESS_TOKEN = previousToken;
    }
  });

  it('passes the nextPageToken to Gmail and filters that page too', async () => {
    const previousFetch = globalThis.fetch;
    const previousToken = process.env.GMAIL_ACCESS_TOKEN;
    process.env.GMAIL_ACCESS_TOKEN = 'test-token';
    const mock = makeGmailMock([agentMessage, ordinaryMessage]);
    globalThis.fetch = mock.fetchMock as typeof fetch;

    try {
      const result = await new GmailConnector().search({ query: 'page-2' }, {}) as {
        messages: unknown[];
        nextPageToken: string | null;
      };
      assert.deepEqual(result.messages, []);
      assert.equal(result.nextPageToken, null);
      assert.equal(mock.requests[0]?.url.searchParams.get('pageToken'), 'page-2');
    } finally {
      globalThis.fetch = previousFetch;
      if (previousToken === undefined) delete process.env.GMAIL_ACCESS_TOKEN;
      else process.env.GMAIL_ACCESS_TOKEN = previousToken;
    }
  });

  it('returns the full message body only for a matching agent recipient', async () => {
    const previousFetch = globalThis.fetch;
    const previousToken = process.env.GMAIL_ACCESS_TOKEN;
    process.env.GMAIL_ACCESS_TOKEN = 'test-token';
    const mock = makeGmailMock([agentMessage, ordinaryMessage]);
    globalThis.fetch = mock.fetchMock as typeof fetch;

    try {
      const connector = new GmailConnector();
      const result = await connector.get(agentMessage.id, {}) as { body: string; subject: string; id: string };
      assert.equal(result.id, agentMessage.id);
      assert.equal(result.subject, 'Agent task');
      assert.equal(result.body, 'Hello agent');
      await assert.rejects(connector.get(ordinaryMessage.id, {}), /not found in the \+agent inbox/);
      await assert.rejects(connector.get('../unrelated', {}), /Invalid Gmail message ID/);
    } finally {
      globalThis.fetch = previousFetch;
      if (previousToken === undefined) delete process.env.GMAIL_ACCESS_TOKEN;
      else process.env.GMAIL_ACCESS_TOKEN = previousToken;
    }
  });
});
