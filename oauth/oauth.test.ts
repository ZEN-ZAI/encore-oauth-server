// tests/oauthEnhanced.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { handler as authHandler, AuthRequest } from "../oauth/authorize";
import { handler as tokenHandler, TokenRequest } from "../oauth/token";
import { handler as userInfoHandler } from "../oauth/getInfo";
import { authCodes, tokens, refreshTokens } from "../oauth/store";
import jwt from "jsonwebtoken";

const signingKey = "your-very-secure-secret"; // must match the key in token.ts

describe("Enhanced OAuth2.0 Server (OIDC, Refresh Tokens, Scopes)", () => {
  // Clear in-memory stores before each test to avoid state leakage
  beforeEach(() => {
    for (const key in authCodes) delete authCodes[key];
    for (const key in tokens) delete tokens[key];
    for (const key in refreshTokens) delete refreshTokens[key];
  });

  it("should generate an auth code with a scope on /oauth/authorize", async () => {
    const req: AuthRequest = {
      response_type: "code",
      client_id: "client-id-123",
      redirect_uri: "http://localhost:3000/callback",
      state: "teststate",
      scope: "openid profile email",
    };

    const result = await authHandler(req);
    expect(result.redirect_url).toContain("http://localhost:3000/callback");

    const url = new URL(result.redirect_url);
    const code = url.searchParams.get("code");
    expect(code).toBeTruthy();
    // Verify the auth code was stored with the correct scope
    expect(authCodes[code!]).toEqual({
      clientId: req.client_id,
      userId: "user-123",
      scope: "openid profile email",
    });
  });

  it("should exchange auth code for tokens (OIDC) on /oauth/token", async () => {
    // First, generate an auth code via the authorize endpoint
    const authReq: AuthRequest = {
      response_type: "code",
      client_id: "client-id-123",
      redirect_uri: "http://localhost:3000/callback",
      scope: "openid profile",
    };

    const authResult = await authHandler(authReq);
    const url = new URL(authResult.redirect_url);
    const code = url.searchParams.get("code");
    expect(code).toBeTruthy();

    // Exchange the auth code for tokens
    const tokenReq: TokenRequest = {
      client_id: "client-id-123",
      client_secret: "secret-abc",
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: "http://localhost:3000/callback",
    };

    const tokenResult = await tokenHandler(tokenReq);
    expect(tokenResult.access_token).toBeTruthy();
    expect(tokenResult.refresh_token).toBeTruthy();
    expect(tokenResult.id_token).toBeTruthy();
    expect(tokenResult.token_type).toBe("Bearer");
    expect(tokenResult.expires_in).toBe(3600);
    expect(tokenResult.scope).toBe("openid profile");

    // Verify the id_token (OIDC) claims
    const decoded = jwt.verify(tokenResult.id_token!, signingKey) as any;
    expect(decoded.sub).toBe("user-123");
    expect(decoded.aud).toBe("client-id-123");
    expect(decoded.iss).toBe("http://localhost:3000");
    expect(decoded.scope).toBe("openid profile");
  });

  it("should return user info for a valid Bearer token", async () => {
    const validToken = "test-access-token";
    // Seed the token store with a valid token
    tokens[validToken] = { accessToken: validToken, userId: "user-123", scope: "openid profile" };

    const headers = { authorization: `Bearer ${validToken}` };
    const response = await userInfoHandler(headers);
    expect(response.userId).toBe("user-123");
    expect(response.scope).toBe("openid profile");
  });

  it("should exchange refresh token for new tokens on /oauth/token", async () => {
    // Generate tokens using the authorization code grant first
    const authReq: AuthRequest = {
      response_type: "code",
      client_id: "client-id-123",
      redirect_uri: "http://localhost:3000/callback",
      scope: "openid",
    };

    const authResult = await authHandler(authReq);
    const url = new URL(authResult.redirect_url);
    const code = url.searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenReq: TokenRequest = {
      client_id: "client-id-123",
      client_secret: "secret-abc",
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: "http://localhost:3000/callback",
    };

    const tokenResult = await tokenHandler(tokenReq);
    const oldRefreshToken = tokenResult.refresh_token;
    expect(oldRefreshToken).toBeTruthy();

    // Use the refresh token to get new tokens
    const refreshReq: TokenRequest = {
      client_id: "client-id-123",
      client_secret: "secret-abc",
      grant_type: "refresh_token",
      refresh_token: oldRefreshToken,
    };

    const refreshResult = await tokenHandler(refreshReq);
    expect(refreshResult.access_token).toBeTruthy();
    expect(refreshResult.refresh_token).toBeTruthy();
    expect(refreshResult.id_token).toBeTruthy();
    expect(refreshResult.token_type).toBe("Bearer");
    expect(refreshResult.expires_in).toBe(3600);
    expect(refreshResult.scope).toBe("openid");

    // Confirm the old refresh token is invalidated
    expect(refreshTokens[oldRefreshToken!]).toBeUndefined();

    // Verify the new id_token's claims
    const decoded = jwt.verify(refreshResult.id_token!, signingKey) as any;
    expect(decoded.sub).toBe("user-123");
    expect(decoded.aud).toBe("client-id-123");
    expect(decoded.iss).toBe("http://localhost:3000");
    expect(decoded.scope).toBe("openid");
  });

  it("should reject a token request with an invalid refresh token", async () => {
    const refreshReq: TokenRequest = {
      client_id: "client-id-123",
      client_secret: "secret-abc",
      grant_type: "refresh_token",
      refresh_token: "invalid-token",
    };

    await expect(tokenHandler(refreshReq)).rejects.toThrow(/Invalid refresh token/);
  });
});
