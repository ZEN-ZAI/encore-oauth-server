// authorize.ts
import { api, APIError } from "encore.dev/api";
import { v4 as uuid } from "uuid";
import { clients, authCodes } from "./store";

export interface AuthRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  state?: string;
  scope?: string; // Support for scopes
}

export interface AuthResponse {
  redirect_url: string;
}

export const auth = api(
  { expose: true, method: "GET", path: "/oauth/authorize" },
  async (p: AuthRequest): Promise<AuthResponse> => handler(p)
);

export async function handler(req: AuthRequest): Promise<AuthResponse> {
  const client = clients.find(
    (c) => c.clientId === req.client_id && c.redirectUri === req.redirect_uri
  );

  if (!client || req.response_type !== "code") {
    throw APIError.invalidArgument("Invalid request");
  }

  // Generate and store a one-time auth code along with scopes
  const code = uuid();
  authCodes[code] = {
    clientId: req.client_id,
    userId: "user-123", // Replace with actual user info after authentication
    scope: req.scope || ""
  };

  const url = new URL(req.redirect_uri);
  url.searchParams.set("code", code);
  if (req.state) url.searchParams.set("state", req.state);

  return {
    redirect_url: url.toString(),
  };
}
