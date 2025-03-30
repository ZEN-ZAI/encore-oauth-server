import { APIError, Header, Gateway } from "encore.dev/api";
import { authHandler } from "encore.dev/auth";
import { OAuthService } from "./application/OAuthService";
import { clientRepository, authCodeRepository, tokenRepository } from "./infrastructure/MemoryInstance";

const oauthService = new OAuthService(clientRepository, authCodeRepository, tokenRepository);

interface AuthParams {
  authorization: Header<"Authorization">;
}

interface AuthData {
  userID: string;
  accessToken: string;
}

export const authHandlerFunction = authHandler<AuthParams, AuthData>(async (params) => {
  const authHeader = params.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw APIError.unauthenticated("Missing or invalid authorization header");
  }
  const accessToken = authHeader.slice("Bearer ".length).trim();
  try {
    oauthService.validateAccessToken(accessToken);
    return { userID: oauthService.getUserIdFromToken(accessToken), accessToken: accessToken };
  } catch {
    throw APIError.unauthenticated("Invalid or expired access token");
  }
});

export const gateway = new Gateway({
  authHandler: authHandlerFunction,
});
