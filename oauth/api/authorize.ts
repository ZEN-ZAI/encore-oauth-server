// api/authorize.ts
import { api, APIError } from "encore.dev/api";
import { OAuthService } from "../application/OAuthService";
import { clientRepository, authCodeRepository, tokenRepository } from "../infrastructure/Repositories";

const oauthService = new OAuthService(clientRepository, authCodeRepository, tokenRepository);

export interface AuthRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  state?: string;
  scope?: string;
}

export interface AuthResponse {
  redirect_url: string;
}

export const authorize = api({ expose: true, method: "GET", path: "/oauth/authorize" }, async (req: AuthRequest): Promise<AuthResponse> => {
  if (req.response_type !== "code") {
    throw APIError.invalidArgument("Unsupported response type");
  }
  const authCode = oauthService.generateAuthCode(req.client_id, req.redirect_uri, req.scope);
  const url = new URL(req.redirect_uri);
  url.searchParams.set("code", authCode.code);
  if (req.state) url.searchParams.set("state", req.state);
  return { redirect_url: url.toString() };
});
