import { api, APIError } from "encore.dev/api";
import { v4 as uuid } from "uuid";
import jwt from "jsonwebtoken";
import { clients, tokens, refreshTokens } from "./store";

export interface RefreshTokenRequest {
  client_id: string;
  client_secret: string;
  refresh_token: string;
}

export interface RefreshTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  id_token: string;
  scope?: string;
}

const issuer = "http://localhost:4000"; // Update with your issuer URL
const signingKey = "your-very-secure-secret"; // Secure this key appropriately

export const refreshToken = api(
  { expose: true, path: "/oauth/refresh", method: "POST" },
  async (req: RefreshTokenRequest): Promise<RefreshTokenResponse> => handler(req)
);

export async function handler(req: RefreshTokenRequest): Promise<RefreshTokenResponse> {
  // Validate presence of refresh token
  if (!req.refresh_token) {
    throw APIError.invalidArgument("Missing refresh token");
  }

  // Check stored refresh token
  const storedRefresh = refreshTokens[req.refresh_token];
  if (!storedRefresh || storedRefresh.clientId !== req.client_id) {
    throw APIError.invalidArgument("Invalid refresh token");
  }

  // Validate client credentials
  const client = clients.find(
    (c) =>
      c.clientId === req.client_id &&
      c.clientSecret === req.client_secret
  );
  if (!client) {
    throw APIError.invalidArgument("Invalid client credentials");
  }

  // Optionally, delete the old refresh token (one-time use)
  delete refreshTokens[req.refresh_token];

  // Generate new tokens
  const accessToken = uuid();
  const newRefreshToken = uuid();
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 3600;
  
  const idToken = jwt.sign(
    {
      sub: storedRefresh.userId,
      aud: req.client_id,
      iss: issuer,
      exp: now + expiresIn,
      iat: now,
      scope: storedRefresh.scope
    },
    signingKey
  );

  tokens[accessToken] = { accessToken, userId: storedRefresh.userId, scope: storedRefresh.scope };
  refreshTokens[newRefreshToken] = { refreshToken: newRefreshToken, clientId: req.client_id, userId: storedRefresh.userId, scope: storedRefresh.scope };

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: newRefreshToken,
    id_token: idToken,
    scope: storedRefresh.scope
  };
}
