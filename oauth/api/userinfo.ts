// api/userinfo.ts
import { api, APIError, Header } from "encore.dev/api";
import { OAuthService } from "../application/OAuthService";
import { clientRepository, authCodeRepository, tokenRepository } from "../infrastructure/Repositories";

const oauthService = new OAuthService(clientRepository, authCodeRepository, tokenRepository);

interface AuthParams {
  authorization: Header<"Authorization">;
}

export interface UserInfoResponse {
  userId: string;
  scope?: string;
}

export const userinfo = api({ expose: true, auth: true, method: "GET", path: "/oauth/userinfo" }, async (headers: AuthParams): Promise<UserInfoResponse> => {
  const authHeader = headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw APIError.unauthenticated("Missing or invalid authorization header");
  }
  const accessToken = authHeader.slice("Bearer ".length).trim();
  try {
    return oauthService.getUserInfo(accessToken);
  } catch (e) {
    throw APIError.unauthenticated("Invalid or expired access token");
  }
});
