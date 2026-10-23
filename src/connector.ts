export interface ConnectorContext { accessToken?: string; userId?: string }
export interface SearchRequest { query?: string; page?: number; pageSize?: number }
export interface ApiConnector {
  search(request: SearchRequest, context: ConnectorContext): Promise<unknown>;
  get(id: string, context: ConnectorContext): Promise<unknown>;
}

import type { GmailMetadata, MetadataCache } from "./storage/metadata-cache.js";

type GmailHeader = { name?: string; value?: string };
type GmailPayload = { headers?: GmailHeader[]; mimeType?: string; body?: { data?: string }; parts?: GmailPayload[] };
type GmailMessage = GmailMetadata & { snippet?: string; payload?: GmailPayload };

const API = "https://gmail.googleapis.com/gmail/v1/users/me";
const AGENT_RECIPIENT = /^[a-z0-9.]+\+agent@gmail\.com$/i;

function headers(message: GmailMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const header of message.payload?.headers ?? []) {
    if (header.name) out[header.name.toLowerCase()] = header.value ?? "";
  }
  return out;
}
function isAgentAddress(address: string): boolean {
  return AGENT_RECIPIENT.test(address.trim().replace(/^<|>$/g, ""));
}
function hasAgentRecipient(message: GmailMessage): boolean {
  const h = headers(message);
  const fields = ["to", "cc", "bcc", "delivered-to", "x-original-to"];
  for (const field of fields) {
    const values = h[field] ?? "";
    const addresses = values.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) ?? [];
    if (addresses.some(isAgentAddress)) return true;
  }
  return false;
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
  constructor(private readonly metadataCache?: MetadataCache<GmailMetadata>) {}

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

  async search(request: SearchRequest, context: ConnectorContext): Promise<unknown> {
    const limit = Math.min(100, Math.max(1, Math.trunc(request.pageSize ?? 50)));
    const params = new URLSearchParams({ maxResults: String(limit), q: "in:anywhere" });
    if (request.query) params.set("pageToken", request.query);
    params.set("includeSpamTrash", "true");
    const page = await this.api<{ messages?: Array<{ id: string }>; nextPageToken?: string; resultSizeEstimate?: number }>("/messages", params);
    const listed = await Promise.all((page.messages ?? []).map(async item => {
      const cached = context.userId ? this.metadataCache?.get(context.userId, item.id) : undefined;
      if (cached) return cached as GmailMessage;

      const metadataParams = new URLSearchParams({ format: "metadata" });
      for (const name of ["To", "Cc", "Bcc", "Delivered-To", "X-Original-To", "From", "Subject", "Date", "X-Spam-Status", "X-Spam-Flag", "X-Google-Spam", "X-Gm-Spam"]) metadataParams.append("metadataHeaders", name);
      const message = await this.api<GmailMessage>("/messages/" + encodeURIComponent(item.id), metadataParams);
      if (context.userId && this.metadataCache) {
        // Cache only metadata returned by Gmail; never cache the full message body.
        this.metadataCache.set(context.userId, item.id, {
          ...(message.id ? { id: message.id } : {}),
          ...(message.threadId ? { threadId: message.threadId } : {}),
          ...(message.internalDate ? { internalDate: message.internalDate } : {}),
          labelIds: message.labelIds ?? [],
          payload: { headers: message.payload?.headers ?? [] },
        });
      }
      return message;
    }));
    const matches = listed.filter(hasAgentRecipient).map(message => {
      const h = headers(message);
      const gmailLabels = message.labelIds ?? [];
      // Gmail exposes its actual spam-folder classification as the SPAM system label.
      // Extra spam-related headers are included only when present; Gmail does not guarantee
      // these headers or expose a numeric spam score through this API.
      const spamHeaders = Object.entries(h)
        .filter(([name]) => /^(x-spam-|x-google-spam$|x-gm-spam$)/i.test(name))
        .map(([name, value]) => ({ name, value }));
      return {
        id: message.id,
        time: h.date ?? (message.internalDate ? new Date(Number(message.internalDate)).toISOString() : null),
        sender: h.from ?? "",
        subject: h.subject ?? "(no subject)",
        spamStatus: gmailLabels.includes("SPAM") ? "marked_spam" : "not_marked_spam",
        spamHints: {
          gmailSpamLabel: gmailLabels.includes("SPAM"),
          gmailLabels,
          headers: spamHeaders,
        },
      };
    });
    return {
      messages: matches,
      nextPageToken: page.nextPageToken ?? null,
      resultSizeEstimate: page.resultSizeEstimate ?? null,
      note: "Only messages with an exact username+agent@gmail.com recipient are returned. Follow nextPageToken to scan older mail.",
    };
  }

  async get(id: string, _context: ConnectorContext): Promise<unknown> {
    if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error("Invalid Gmail message ID.");
    const message = await this.api<GmailMessage>("/messages/" + encodeURIComponent(id), new URLSearchParams({ format: "full" }));
    if (!hasAgentRecipient(message)) throw new Error("Message not found in the +agent inbox.");
    const h = headers(message);
    return {
      id: message.id,
      time: h.date ?? (message.internalDate ? new Date(Number(message.internalDate)).toISOString() : null),
      sender: h.from ?? "",
      subject: h.subject ?? "(no subject)",
      to: h.to ?? "",
      cc: h.cc ?? "",
      body: decodeBody(message),
      snippet: message.snippet ?? "",
    };
  }
}
