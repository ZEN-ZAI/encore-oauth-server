// api/userinfo.ts
import { api } from "encore.dev/api";
import { OAuthService } from "../application/OAuthService";
import { clientRepository, authCodeRepository, tokenRepository } from "../infrastructure/MemoryInstance";
import { getAuthData } from "~encore/auth";

const oauthService = new OAuthService(clientRepository, authCodeRepository, tokenRepository);

export interface UserInfoResponse {
  userId: string;
  scope?: string;
}

export const userinfo = api({ expose: true, auth: true, method: "GET", path: "/oauth/userinfo" }, async (): Promise<UserInfoResponse> => {
  // const userID = getAuthData()!.userID;
  const accessToken = getAuthData()!.accessToken;
  return oauthService.getUserInfo(accessToken);
});
