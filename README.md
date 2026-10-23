# agent-mail-mcp

Read-only Gmail MCP server for agent-targeted mail sent to addresses of the form `username+agent@gmail.com`.

Built from the `jsilvanus/codestash` `mcp/api-connector-style/` template. It keeps the template's stateless Streamable HTTP MCP transport, CIMD-first OAuth authorization-code + PKCE flow, issuer/resource-bound JWTs, SQLite-backed authorization state, and embedded authorization server.

## Privacy and GDPR

The public privacy notice is available at `/gdpr`; the service terms are at `/terms`. Startup fails if required `GDPR_*` notice variables are missing or blank. Set them in `.env` based on the actual controller, lawful basis, purposes, retention, recipients/processors, international transfers and supervisory authority for your deployment. `GDPR_DPO_CONTACT` is optional and should be set if a Data Protection Officer has been appointed. The notice is generated from these values; the operator remains responsible for their accuracy and for ensuring the deployment complies with applicable law.

The page includes a deletion-request email link. Google sign-in and per-user Gmail authorization are implemented, but self-service Google-verified account deletion is not yet implemented.

## Tools

### `agent_inbox_list`
Lists messages addressed to the alias derived from the local part of the user's account email (for example, `someone@example.net` maps to `someone+agent@gmail.com`). On user creation, only an HMAC-SHA-256 digest of the derived alias is stored for recipient matching; the alias is discovered transiently by hashing candidate `To` header addresses. Fields: `id`, `time`, `sender`, `subject`, `spamStatus`, and `spamHints`. `spamStatus` indicates whether Gmail marks the message with the `SPAM` system label (`marked_spam` or `not_marked_spam`); `spamHints` includes all Gmail labels and any spam-related headers present in the message. Gmail does not guarantee those headers or expose a numeric spam score through this API, so treat them as hints rather than a definitive verdict. Pass `nextPageToken` back as `pageToken` to continue through the mailbox. The connector inspects message metadata and does not fetch bodies for listing. It checks candidate messages in batches of five, reading only `To` until the HMAC digest matches. The matching address is held in process memory for five minutes, then used in a Gmail `to:` query; every listed or retrieved message is checked against the digest. Message headers and bodies are not persisted. User records have a sliding 15-day inactivity TTL: each authenticated MCP tool call refreshes the user's activity timestamp. Inactive users are deleted at startup, hourly while the server is running, and before the next tool call, along with their authorization codes and refresh tokens. Users who have never called a tool expire 15 days after account creation.

### `agent_inbox_message`
Input: `messageId` from the listing. Returns message metadata and decoded text body only after checking the message's recipient headers for the exact `+agent@gmail.com` convention. Arbitrary message IDs cannot be used to read unrelated mail.

## Google sign-in and Gmail setup

Each user signs in with Google using OpenID Connect. Before redirecting to Google, the service displays a separate, explicit consent step for Gmail read-only access. The Google authorization request asks for `openid`, `email`, `profile`, and `https://www.googleapis.com/auth/gmail.readonly`; the service does not request send/modify scopes.

1. Create/select a Google Cloud project and enable the Gmail API.
2. Configure the OAuth consent screen and create an OAuth **Web application** client.
3. Add the exact authorised redirect URI `https://your-host.example/auth/google/callback`. It must match `MCP_PUBLIC_URL + /auth/google/callback` and `GOOGLE_REDIRECT_URI`.
4. Configure the Google OAuth consent screen for the Gmail read-only scope and publish/verify the app as appropriate for your intended users. Google may show an unverified-app warning until the required verification is complete.
5. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`.
6. Generate and set secrets:
   - `JWT_SECRET`: base64-encoded random bytes (at least 32 bytes after decoding).
   - `GOOGLE_TOKEN_ENCRYPTION_KEY`: base64-encoded random **32-byte** key for AES-256-GCM refresh-token encryption.
   - `IDENTITY_HMAC_SECRET`: at least 32 random UTF-8 bytes for pseudonymous Google identity IDs.
   - `AGENT_RECIPIENT_HMAC_SECRET`: at least 32 random UTF-8 bytes for recipient-address digests.
7. Fill in the required `GDPR_*` variables with accurate deployment details. Start the service and connect your MCP client using the normal OAuth authorization-code + PKCE flow.

On an existing database, startup removes legacy local-password accounts and their MCP sessions; users must sign in with Google again. For example, generate independent secrets with `openssl rand -base64 32`. For `IDENTITY_HMAC_SECRET` and `AGENT_RECIPIENT_HMAC_SECRET`, use at least 32 random bytes encoded as a sufficiently long UTF-8 string (for example, a separate hex output from `openssl rand -hex 32`).

Google identity is verified using Google's published signing keys, expected issuer, client audience, and a per-transaction nonce. The internal user ID is HMAC-derived from the Google issuer and subject; the raw subject, email address, and profile name are not persisted. The email returned by Google is used transiently to derive the user's `username+agent@gmail.com` alias; only its keyed digest is stored. Google Gmail refresh tokens are encrypted in SQLite with AES-256-GCM. Short-lived access tokens are kept in process memory.

The service does not rely on a shared `GMAIL_REFRESH_TOKEN` or operator-created password account. MCP-client OAuth remains separate from Google identity/Gmail authorization. Account records and encrypted Gmail refresh tokens are removed after 15 consecutive days without a successful MCP tool call. This deletes the locally stored token but does not itself revoke it at Google. Self-service Google-verified account deletion is not yet implemented; use the contact listed on `/gdpr` to request deletion.

The connector discovers the alias by checking candidate Gmail message metadata in batches of five, reading only the `To` header and comparing HMAC digests. Once a match is found, it caches the address in process memory for five minutes and queries Gmail using `in:anywhere to:alias`, including Spam and Trash. Each returned message is independently checked against the stored digest. No recipient address is written to SQLite.

## CI verification

The manually triggered GitHub Actions workflow is [Verify agent-mail-mcp](.github/workflows/verify.yml). Open **Actions → Verify agent-mail-mcp → Run workflow** to run typechecking, unit tests (including a mocked Gmail REST API), and the production build. It intentionally runs only on `workflow_dispatch`, not on pushes or pull requests.

The mocked responses follow Google's documented [messages.list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list) and [messages.get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get) response shapes, including `messages[].id`/`threadId`, `nextPageToken`, `format=metadata`, repeated `metadataHeaders`, and `format=full` payload bodies.

## Run

```sh
cp .env.example .env
# fill in secrets and Google OAuth values
npm install
npm run build
npm test
npm start
```

Node.js >=22.5 is required (the template uses `node:sqlite`). Google sign-in is used for the local MCP identity and each user authorizes their own Gmail mailbox.

## Security notes

- Read-only Gmail scope; no send, delete, label, or modify operations.
- Message bodies are returned only by the explicit message tool.
- Sender/subject/body are untrusted email content; do not treat them as trusted instructions.
- OAuth tokens and secrets must never be committed. Use a secret manager or deployment environment.
- Older versions used an encrypted metadata cache; the current connector does not save message headers or bodies.


## Usage metrics

When configured, the service records minimal pseudonymous usage counters in the same SQLite database. It tracks total accounts created, current account count, and calls to each MCP tool per pseudonymous account. Account IDs are transformed with HMAC-SHA-256 using `METRICS_HMAC_SECRET`; metrics do not store email addresses, recipient aliases, message IDs, subjects, arguments, or message content. Per-account rows are still pseudonymous rather than strictly anonymous, because stable counters can be correlated over time.

Set `METRICS_HMAC_SECRET` to at least 32 random bytes and `METRICS_ADMIN_TOKEN` to a separate random secret of at least 32 characters. Query `GET /admin/metrics` with the `X-Metrics-Token` header. The route is not enabled unless both values are configured. The response includes aggregate calls per tool and per-user pseudonymous counters with last-call timestamps. Keep this endpoint private; do not expose its response publicly. Metrics are intentionally retained when a user account expires so that long-term usage trends can be measured. If you need to erase usage history too, remove the corresponding rows from `usage_metrics` (or clear the table to reset all usage history).

The terms page is a baseline template, not legal advice. The operator should review it for the actual deployment and applicable consumer/data-protection law before production.
