export interface AuthorizationCodeRecord {
  code: string;
  clientId: string;
  redirectUri: string;
  challenge: string;
  subject: string;
  scope: string;
  expires: number;
}

export interface RefreshTokenRecord {
  token: string;
  clientId: string;
  subject: string;
  scope: string;
  expires: number;
}

export interface AuthStore {
  saveAuthorizationCode(record: AuthorizationCodeRecord): void;
  consumeAuthorizationCode(code: string): AuthorizationCodeRecord | undefined;
  saveRefreshToken(record: RefreshTokenRecord): void;
  getRefreshToken(token: string): RefreshTokenRecord | undefined;
}

export interface McpUser {
  id: string;
  name: string;
  email?: string;
  /** HMAC of the derived username+agent@gmail.com address; never the address itself. */
  agentRecipientHash?: string;
  passwordHash?: string;
  createdAt: number;
  lastToolCallAt?: number;
}

export interface UserStore {
  createUser(user: McpUser): void;
  listUsers(): McpUser[];
  getUser(id: string): McpUser | undefined;
  getUserByEmail(email: string): McpUser | undefined;
  updateAgentRecipientHash(id: string, digest: string): McpUser | undefined;
  updateUser(id: string, patch: { name?: string; email?: string; passwordHash?: string }): McpUser | undefined;
  deleteUser(id: string): boolean;
  /** Refresh the sliding 15-day inactivity TTL; expired users and their stored state are removed first. */
  recordToolCall(id: string): boolean;
  /** Delete users inactive for 15 days, along with their authorization and cached metadata. */
  pruneInactiveUsers(): number;
}
