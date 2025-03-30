// getInfo.ts
import { api, APIError, Header } from "encore.dev/api";
import log from "encore.dev/log";
import { tokens } from "./store";

interface AuthParams {
  authorization: Header<"Authorization">;
}

export interface UserInfoResponse {
  userId: string;
  scope?: string;
}

export const get = api({ expose: true, method: "GET", path: "/oauth/userinfo" }, async (p: AuthParams): Promise<UserInfoResponse> => {
  return handler(p);
});

export async function handler(headers: AuthParams): Promise<UserInfoResponse> {
  log.info("log headers", headers);

  const authHeader = headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw APIError.unauthenticated("Missing or invalid authorization header");
  }

  const accessToken = headers.authorization.slice("Bearer ".length).trim();

  const tokenEntry = tokens[accessToken];
  if (!tokenEntry) {
    throw APIError.unauthenticated("Invalid or expired access token");
  }

  return {
    userId: tokenEntry.userId,
    scope: tokenEntry.scope,
  };
}
