import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest, CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { ApiConnector, ConnectorContext } from '../connector.js';

type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;
const oauthSecuritySchemes = [{ type: 'oauth2' as const, scopes: ['mcp'] }];
function withOAuthSecurity<T extends object>(config: T): T & { securitySchemes: typeof oauthSecuritySchemes } { return { ...config, securitySchemes: oauthSecuritySchemes }; }
function contextFromExtra(extra: Extra): ConnectorContext {
  const auth = extra.authInfo;
  return { ...(auth?.token ? { accessToken: auth.token } : {}), ...(typeof auth?.extra?.userId === 'string' ? { userId: auth.extra.userId } : {}) };
}
function result(value: unknown): CallToolResult { return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] }; }
function authError(publicUrl: string): CallToolResult {
  return { content: [{ type: 'text', text: 'Authentication required.' }], isError: true, _meta: { 'mcp/www_authenticate': ['Bearer resource_metadata="' + publicUrl + '/.well-known/oauth-protected-resource/mcp", scope="mcp", error="insufficient_scope", error_description="Sign in to use this tool."'] } };
}
function errorResult(error: unknown): CallToolResult { return { content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }], isError: true }; }

export function createMcpServer(options: { connector: ApiConnector; publicUrl: string }): McpServer {
  const server = new McpServer({ name: 'agent-mail-mcp', version: '2.0.0' });
  server.registerTool('agent_inbox_list', withOAuthSecurity({
    description: 'List emails addressed to username+agent@gmail.com. Returns only message ID, time, sender and subject; excludes all other mail. Use nextPageToken to continue through older mail.',
    inputSchema: { pageToken: z.string().optional().describe('Gmail nextPageToken from the previous result.'), limit: z.number().int().min(1).max(100).optional().describe('Maximum Gmail page size (1–100). Defaults to 50.') },
  }), async (args, extra) => {
    if (!extra.authInfo?.token) return authError(options.publicUrl);
    try {
      return result(await options.connector.search({ ...(args.pageToken ? { query: args.pageToken } : {}), ...(args.limit ? { pageSize: args.limit } : {}) }, contextFromExtra(extra)));
    } catch (error) { return errorResult(error); }
  });
  server.registerTool('agent_inbox_message', withOAuthSecurity({
    description: 'Retrieve one email by Gmail message ID, but only if its recipients include an exact username+agent@gmail.com address. Returns metadata and decoded text body.',
    inputSchema: { messageId: z.string().min(1).describe('Gmail message ID returned by agent_inbox_list.') },
  }), async (args, extra) => {
    if (!extra.authInfo?.token) return authError(options.publicUrl);
    try { return result(await options.connector.get(args.messageId, contextFromExtra(extra))); }
    catch (error) { return errorResult(error); }
  });
  return server;
}
