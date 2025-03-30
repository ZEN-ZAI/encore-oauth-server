// token.ts
import { api, APIError } from "encore.dev/api";
import { v4 as uuid } from "uuid";
import jwt from "jsonwebtoken";
import { clients, authCodes, tokens, refreshTokens } from "./store";

export interface TokenRequest {
  client_id: string;
  client_secret: string;
  grant_type: string;
  code?: string;
  redirect_uri?: string;
  refresh_token?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

const issuer = "http://localhost:3000"; // Update to your issuer URL
const signingKey = "your-very-secure-secret"; // Secure this key properly

export const token = api(
  { expose: true, path: "/oauth/token", method: "POST" },
  async (p: TokenRequest): Promise<TokenResponse> => handler(p)
);

export async function handler(req: TokenRequest): Promise<TokenResponse> {
  // --- Authorization Code Grant ---
  if (req.grant_type === "authorization_code") {
    if (!req.code) {
      throw APIError.invalidArgument("Missing authorization code");
    }

    const client = clients.find(
      (c) =>
        c.clientId === req.client_id &&
        c.clientSecret === req.client_secret &&
        c.redirectUri === req.redirect_uri
    );
    if (!client) {
      throw APIError.invalidArgument("Invalid client credentials");
    }

    const authCodeEntry = authCodes[req.code];
    if (!authCodeEntry || authCodeEntry.clientId !== req.client_id) {
      throw APIError.invalidArgument("Invalid or expired authorization code");
    }
    // Invalidate the auth code (one-time use)
    delete authCodes[req.code];

    // Generate tokens
    const accessToken = uuid();
    const refreshToken = uuid();
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 3600;
    const idToken = jwt.sign(
      {
        sub: authCodeEntry.userId,
        aud: req.client_id,
        iss: issuer,
        exp: now + expiresIn,
        iat: now,
        scope: authCodeEntry.scope || ""
      },
      signingKey
    );

    tokens[accessToken] = { accessToken, userId: authCodeEntry.userId, scope: authCodeEntry.scope || "" };
    refreshTokens[refreshToken] = { refreshToken, clientId: req.client_id, userId: authCodeEntry.userId, scope: authCodeEntry.scope || "" };

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: expiresIn,
      refresh_token: refreshToken,
      id_token: idToken,
      scope: authCodeEntry.scope || ""
    };
  }

  // --- Refresh Token Grant ---
  if (req.grant_type === "refresh_token") {
    if (!req.refresh_token) {
      throw APIError.invalidArgument("Missing refresh token");
    }
    const storedRefresh = refreshTokens[req.refresh_token];
    if (!storedRefresh || storedRefresh.clientId !== req.client_id) {
      throw APIError.invalidArgument("Invalid refresh token");
    }
    const client = clients.find(
      (c) =>
        c.clientId === req.client_id &&
        c.clientSecret === req.client_secret
    );
    if (!client) {
      throw APIError.invalidArgument("Invalid client credentials");
    }

    // Optionally, delete the old refresh token and issue a new one
    delete refreshTokens[req.refresh_token];

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

  throw APIError.invalidArgument("Unsupported grant type");
}
