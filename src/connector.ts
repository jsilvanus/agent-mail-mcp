export interface ConnectorContext { accessToken?: string; userId?: string; agentRecipientHash?: string }
export interface SearchRequest { query?: string; page?: number; pageSize?: number }
export interface ApiConnector {
  search(request: SearchRequest, context: ConnectorContext): Promise<unknown>;
  get(id: string, context: ConnectorContext): Promise<unknown>;
}

type GmailHeader = { name?: string; value?: string };
type GmailPayload = { headers?: GmailHeader[]; mimeType?: string; body?: { data?: string }; parts?: GmailPayload[] };
type GmailMessage = { id?: string; threadId?: string; internalDate?: string; labelIds?: string[]; snippet?: string; payload?: GmailPayload };

import { recipientDigestMatches } from "./recipient-hmac.js";

const API = "https://gmail.googleapis.com/gmail/v1/users/me";
const AGENT_RECIPIENT = /^[a-z0-9.]+\+agent@gmail\.com$/i;

function headers(message: GmailMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const header of message.payload?.headers ?? []) {
    if (header.name) out[header.name.toLowerCase()] = header.value ?? "";
  }
  return out;
}
function toAddresses(message: GmailMessage): string[] {
  const value = headers(message).to ?? "";
  return value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/gi) ?? [];
}
function hasAgentRecipient(message: GmailMessage, digest?: string): boolean {
  if (!digest) return false;
  return toAddresses(message).some(address =>
    AGENT_RECIPIENT.test(address.trim()) && recipientDigestMatches(address, digest)
  );
}
function decodeBody(message: GmailMessage): string {
  const payload = message.payload;
  if (!payload) return "";
  if (payload.body?.data && (!payload.mimeType || payload.mimeType.startsWith("text/"))) {
    return Buffer.from(payload.body.data, "base64url").toString("utf8");
  }
  const parts = payload.parts ?? [];
  const plain = parts.find(p => p.mimeType === "text/plain");
  if (plain) return decodeBody({ payload: plain });
  const html = parts.find(p => p.mimeType === "text/html");
  if (html) return decodeBody({ payload: html });
  return parts.map(p => decodeBody({ payload: p })).filter(Boolean).join("\n");
}

export class GmailConnector implements ApiConnector {
  private accessToken?: string;
  private accessTokenExpiresAt = 0;

  private async token(): Promise<string> {
    const staticToken = process.env.GMAIL_ACCESS_TOKEN;
    if (staticToken) return staticToken;
    const clientId = process.env.GMAIL_CLIENT_ID;
    const clientSecret = process.env.GMAIL_CLIENT_SECRET;
    const refreshToken = process.env.GMAIL_REFRESH_TOKEN;
    if (!clientId || !clientSecret || !refreshToken) {
      throw new Error("Gmail is not configured. Set GMAIL_ACCESS_TOKEN or GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET and GMAIL_REFRESH_TOKEN.");
    }
    if (this.accessToken && Date.now() < this.accessTokenExpiresAt - 60_000) return this.accessToken;
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, refresh_token: refreshToken, grant_type: "refresh_token" }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error("Gmail OAuth token refresh failed (" + response.status + ").");
    const value = await response.json() as { access_token?: string; expires_in?: number };
    if (!value.access_token) throw new Error("Gmail OAuth response did not contain an access token.");
    this.accessToken = value.access_token;
    this.accessTokenExpiresAt = Date.now() + (value.expires_in ?? 3600) * 1000;
    return value.access_token;
  }

  private async api<T>(path: string, params?: URLSearchParams): Promise<T> {
    const url = new URL(API + path);
    if (params) url.search = params.toString();
    const response = await fetch(url, {
      headers: { authorization: "Bearer " + await this.token(), accept: "application/json" },
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 500);
      throw new Error("Gmail API request failed (" + response.status + "): " + detail);
    }
    return await response.json() as T;
  }

  private readonly discoveredAliases = new Map<string, { address: string; expiresAt: number }>();

  private async discoverAlias(digest: string): Promise<string> {
    const cached = this.discoveredAliases.get(digest);
    if (cached && cached.expiresAt > Date.now()) return cached.address;
    this.discoveredAliases.delete(digest);

    // Inspect only To headers in small batches until a candidate hashes to this user's digest.
    let pageToken: string | undefined;
    do {
      const params = new URLSearchParams({ maxResults: "5", q: "in:anywhere", includeSpamTrash: "true" });
      if (pageToken) params.set("pageToken", pageToken);
      const page = await this.api<{ messages?: Array<{ id: string }>; nextPageToken?: string }>("/messages", params);
      const candidates = await Promise.all((page.messages ?? []).map(async item => {
        const metadataParams = new URLSearchParams({ format: "metadata", metadataHeaders: "To" });
        return this.api<GmailMessage>("/messages/" + encodeURIComponent(item.id), metadataParams);
      }));
      for (const candidate of candidates) {
        for (const address of toAddresses(candidate)) {
          if (AGENT_RECIPIENT.test(address.trim()) && recipientDigestMatches(address, digest)) {
            this.discoveredAliases.set(digest, { address: address.trim(), expiresAt: Date.now() + 5 * 60_000 });
            return address.trim();
          }
        }
      }
      pageToken = page.nextPageToken;
    } while (pageToken);
    throw new Error("Could not discover a matching +agent recipient in the mailbox.");
  }

  async search(request: SearchRequest, context: ConnectorContext): Promise<unknown> {
    if (!context.agentRecipientHash) throw new Error("No +agent recipient digest is configured for this user.");
    const alias = await this.discoverAlias(context.agentRecipientHash);
    const limit = Math.min(100, Math.max(1, Math.trunc(request.pageSize ?? 50)));
    const params = new URLSearchParams({ maxResults: String(limit), q: "in:anywhere to:" + alias, includeSpamTrash: "true" });
    if (request.query) params.set("pageToken", request.query);
    const page = await this.api<{ messages?: Array<{ id: string }>; nextPageToken?: string; resultSizeEstimate?: number }>("/messages", params);
    const listed = await Promise.all((page.messages ?? []).map(async item => {
      const metadataParams = new URLSearchParams({ format: "metadata" });
      for (const name of ["To", "From", "Subject", "Date", "X-Spam-Status", "X-Spam-Flag", "X-Google-Spam", "X-Gm-Spam"]) metadataParams.append("metadataHeaders", name);
      return this.api<GmailMessage>("/messages/" + encodeURIComponent(item.id), metadataParams);
    }));
    const matches = listed.filter(message => hasAgentRecipient(message, context.agentRecipientHash)).map(message => {
      const h = headers(message);
      const gmailLabels = message.labelIds ?? [];
      const spamHeaders = Object.entries(h)
        .filter(([name]) => /^(x-spam-|x-google-spam$|x-gm-spam$)/i.test(name))
        .map(([name, value]) => ({ name, value }));
      return {
        id: message.id,
        time: h.date ?? (message.internalDate ? new Date(Number(message.internalDate)).toISOString() : null),
        sender: h.from ?? "",
        subject: h.subject ?? "(no subject)",
        spamStatus: gmailLabels.includes("SPAM") ? "marked_spam" : "not_marked_spam",
        spamHints: { gmailSpamLabel: gmailLabels.includes("SPAM"), gmailLabels, headers: spamHeaders },
      };
    });
    return {
      messages: matches,
      nextPageToken: page.nextPageToken ?? null,
      resultSizeEstimate: page.resultSizeEstimate ?? null,
      note: "Only messages whose To header matches this user's stored +agent HMAC digest are returned. Pass nextPageToken to continue.",
    };
  }

  async get(id: string, context: ConnectorContext): Promise<unknown> {
    if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error("Invalid Gmail message ID.");
    if (!context.agentRecipientHash) throw new Error("No +agent recipient digest is configured for this user.");
    const message = await this.api<GmailMessage>("/messages/" + encodeURIComponent(id), new URLSearchParams({ format: "full" }));
    if (!hasAgentRecipient(message, context.agentRecipientHash)) throw new Error("Message not found in the +agent inbox.");
    const h = headers(message);
    return {
      id: message.id,
      time: h.date ?? (message.internalDate ? new Date(Number(message.internalDate)).toISOString() : null),
      sender: h.from ?? "",
      subject: h.subject ?? "(no subject)",
      to: h.to ?? "",
      body: decodeBody(message),
      snippet: message.snippet ?? "",
    };
  }
}
