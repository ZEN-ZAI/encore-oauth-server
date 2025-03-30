// tests/oauthEnhanced.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import jwt from "jsonwebtoken";

import { OAuthService } from "./application/OAuthService";
import { InMemoryClientRepository, InMemoryAuthCodeRepository, InMemoryTokenRepository } from "./infrastructure/MemoryRepository";

const signingKey = "your-very-secure-secret"; // Must match the key used in OAuthService

let oauthService: OAuthService;
let clientRepo: InMemoryClientRepository;
let authCodeRepo: InMemoryAuthCodeRepository;
let tokenRepo: InMemoryTokenRepository;

describe("Enhanced OAuth2.0 Server (DDD) - OAuthService", () => {
  // Reinitialize repositories and service for each test to avoid state leakage
  beforeEach(() => {
    clientRepo = new InMemoryClientRepository();
    authCodeRepo = new InMemoryAuthCodeRepository();
    tokenRepo = new InMemoryTokenRepository();
    oauthService = new OAuthService(clientRepo, authCodeRepo, tokenRepo);
  });

  it("should generate an auth code with a scope", () => {
    const authCode = oauthService.generateAuthCode("client-id-123", "http://localhost:3000/callback", "openid profile email");
    expect(authCode.code).toBeTruthy();
    // The auth code should be stored in the repository
    const stored = authCodeRepo.getByCode(authCode.code);
    expect(stored).toEqual(authCode);
  });

  it("should exchange auth code for tokens (OIDC)", () => {
    // First, generate an auth code with a scope.
    const authCode = oauthService.generateAuthCode("client-id-123", "http://localhost:3000/callback", "openid profile");
    // Exchange the auth code for tokens.
    const result = oauthService.exchangeAuthCodeForToken("client-id-123", "secret-abc", "http://localhost:3000/callback", authCode.code);
    expect(result.token.accessToken).toBeTruthy();
    expect(result.refreshToken).toBeTruthy();
    expect(result.idToken).toBeTruthy();
    expect(result.token.expiresIn).toBe(3600);
    expect(result.token.scope).toBe("openid profile");

    // Verify the id_token (OIDC) claims.
    const decoded = jwt.verify(result.idToken, signingKey) as any;
    expect(decoded.sub).toBe("user-123");
    expect(decoded.aud).toBe("client-id-123");
    expect(decoded.iss).toBe("http://localhost:3000");
    expect(decoded.scope).toBe("openid profile");
  });

  it("should exchange refresh token for new tokens", () => {
    // Generate tokens using the authorization code grant.
    const authCode = oauthService.generateAuthCode("client-id-123", "http://localhost:3000/callback", "openid");
    const tokenResult = oauthService.exchangeAuthCodeForToken("client-id-123", "secret-abc", "http://localhost:3000/callback", authCode.code);
    const oldRefreshToken = tokenResult.refreshToken;
    expect(oldRefreshToken).toBeTruthy();

    // Use the refresh token to get new tokens.
    const refreshResult = oauthService.refreshToken("client-id-123", "secret-abc", oldRefreshToken);
    expect(refreshResult.token.accessToken).toBeTruthy();
    expect(refreshResult.newRefreshToken).toBeTruthy();
    expect(refreshResult.idToken).toBeTruthy();
    expect(refreshResult.token.scope).toBe("openid");

    // Verify the new id_token's claims.
    const decoded = jwt.verify(refreshResult.idToken, signingKey) as any;
    expect(decoded.sub).toBe("user-123");
    expect(decoded.aud).toBe("client-id-123");
    expect(decoded.iss).toBe("http://localhost:3000");
    expect(decoded.scope).toBe("openid");

    // Confirm the old refresh token is invalidated.
    const tokenByOldRefresh = tokenRepo.getTokenByRefreshToken(oldRefreshToken);
    expect(tokenByOldRefresh).toBeUndefined();
  });

  it("should get user info for a valid access token", () => {
    // Generate tokens via auth code grant.
    const authCode = oauthService.generateAuthCode("client-id-123", "http://localhost:3000/callback", "openid profile");
    const tokenResult = oauthService.exchangeAuthCodeForToken("client-id-123", "secret-abc", "http://localhost:3000/callback", authCode.code);
    const accessToken = tokenResult.token.accessToken;
    // Retrieve user info using the access token.
    const userInfo = oauthService.getUserInfo(accessToken);
    expect(userInfo.userId).toBe("user-123");
    expect(userInfo.scope).toBe("openid profile");
  });
});
