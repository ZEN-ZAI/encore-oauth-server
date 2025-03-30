// api/token.ts
import { api, APIError } from "encore.dev/api";
import { OAuthService } from "../application/OAuthService";
import { clientRepository, authCodeRepository, tokenRepository } from "../infrastructure/MemoryInstance";

const oauthService = new OAuthService(clientRepository, authCodeRepository, tokenRepository);

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

export const token = api({ expose: true, path: "/oauth/token", method: "POST" }, async (req: TokenRequest): Promise<TokenResponse> => {
  if (req.grant_type === "authorization_code") {
    if (!req.code || !req.redirect_uri) {
      throw APIError.invalidArgument("Missing parameters");
    }
    const result = oauthService.exchangeAuthCodeForToken(req.client_id, req.client_secret, req.redirect_uri, req.code);
    return {
      access_token: result.token.accessToken,
      token_type: "Bearer",
      expires_in: result.token.expiresIn,
      refresh_token: result.refreshToken,
      id_token: result.idToken,
      scope: result.token.scope,
    };
  } else if (req.grant_type === "refresh_token") {
    if (!req.refresh_token) {
      throw APIError.invalidArgument("Missing refresh token");
    }
    const result = oauthService.refreshToken(req.client_id, req.client_secret, req.refresh_token);
    return {
      access_token: result.token.accessToken,
      token_type: "Bearer",
      expires_in: result.token.expiresIn,
      refresh_token: result.newRefreshToken,
      id_token: result.idToken,
      scope: result.token.scope,
    };
  } else {
    throw APIError.invalidArgument("Unsupported grant type");
  }
});
