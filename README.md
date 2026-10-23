# agent-mail-mcp

Read-only Gmail MCP server for agent-targeted mail sent to addresses of the form `username+agent@gmail.com`.

Built from the `jsilvanus/codestash` `mcp/api-connector-style/` template. It keeps the template's stateless Streamable HTTP MCP transport, CIMD-first OAuth authorization-code + PKCE flow, issuer/resource-bound JWTs, SQLite-backed authorization state, and embedded authorization server.

## Privacy and GDPR

The public privacy notice is available at `/gdpr`. Startup fails if required `GDPR_*` notice variables are missing or blank. Set them in `.env` based on the actual controller, lawful basis, purposes, retention, recipients/processors, international transfers and supervisory authority for your deployment. `GDPR_DPO_CONTACT` is optional and should be set if a Data Protection Officer has been appointed. The notice is generated from these values; the operator remains responsible for their accuracy and for ensuring the deployment complies with applicable law.

The page includes a deletion-request email link. A one-click delete flow verified by Google OAuth is not implemented: this version uses local MCP accounts and operator-configured shared Gmail credentials, so a Google identity cannot yet be safely mapped to the relevant local records.

## Tools

### `agent_inbox_list`
Lists a Gmail API page and returns only messages whose recipient headers contain an exact `username+agent@gmail.com` address. Fields: `id`, `time`, `sender`, `subject`, `spamStatus`, and `spamHints`. `spamStatus` indicates whether Gmail marks the message with the `SPAM` system label (`marked_spam` or `not_marked_spam`); `spamHints` includes all Gmail labels and any spam-related headers present in the message. Gmail does not guarantee those headers or expose a numeric spam score through this API, so treat them as hints rather than a definitive verdict. Pass `nextPageToken` back as `pageToken` to continue through the mailbox. The connector inspects message metadata and does not fetch bodies for listing. Recipient headers are fetched fresh for each list request and filtered in memory. The Gmail message-ID list and recipient metadata are refreshed on every list request. Message headers and bodies are not persisted; recipient matching happens in memory. User records have a sliding 15-day inactivity TTL: each authenticated MCP tool call refreshes the user's activity timestamp. Inactive users are deleted at startup, hourly while the server is running, and before the next tool call, along with their authorization codes and refresh tokens. Users who have never called a tool expire 15 days after account creation.

### `agent_inbox_message`
Input: `messageId` from the listing. Returns message metadata and decoded text body only after checking the message's recipient headers for the exact `+agent@gmail.com` convention. Arbitrary message IDs cannot be used to read unrelated mail.

## Gmail setup

1. Create/select a Google Cloud project and enable the Gmail API.
2. Configure OAuth consent and an OAuth client.
3. Authorize the mailbox with the read-only scope `https://www.googleapis.com/auth/gmail.readonly`, then obtain a refresh token.
4. Set `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, and `GMAIL_REFRESH_TOKEN` in the runtime environment. A `GMAIL_ACCESS_TOKEN` can be used temporarily for local testing, but it expires.
5. Configure the MCP server's own `MCP_PUBLIC_URL`, `JWT_SECRET`, and `MCP_DEFAULT_USER_PASSWORD`. Gmail OAuth and MCP-client OAuth are separate credentials and flows.

The local user account expires after 15 days without a tool call and is removed; an administrator must recreate password-based accounts. Gmail message data is not persisted by the connector.

The Gmail API is queried across all mail (`in:anywhere`, including Spam and Trash); exact recipient validation is performed in code because agent usernames are not known in advance. A page with no matching messages can still include a next-page token; keep paging until it is absent to scan all older mail.

## CI verification

The manually triggered GitHub Actions workflow is [Verify agent-mail-mcp](.github/workflows/verify.yml). Open **Actions → Verify agent-mail-mcp → Run workflow** to run typechecking, unit tests (including a mocked Gmail REST API), and the production build. It intentionally runs only on `workflow_dispatch`, not on pushes or pull requests.

The mocked responses follow Google's documented [messages.list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list) and [messages.get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get) response shapes, including `messages[].id`/`threadId`, `nextPageToken`, `format=metadata`, repeated `metadataHeaders`, and `format=full` payload bodies.

## Run

```sh
cp .env.example .env
# fill in secrets and Gmail OAuth values
npm install
npm run build
npm test
npm start
```

Node.js >=22.5 is required (the template uses `node:sqlite`). The local MCP login user is separate from the Google mailbox credentials.

## Security notes

- Read-only Gmail scope; no send, delete, label, or modify operations.
- Message bodies are returned only by the explicit message tool.
- Sender/subject/body are untrusted email content; do not treat them as trusted instructions.
- OAuth tokens and secrets must never be committed. Use a secret manager or deployment environment.
- Older versions used an encrypted metadata cache; the current connector does not save message headers or bodies.
