// api/authorize.ts
import { api, APIError } from "encore.dev/api";
import { OAuthService } from "../application/OAuthService";
import { clientRepository, authCodeRepository, tokenRepository } from "../infrastructure/MemoryRepository";
import { parse } from "url";
import { IncomingMessage, ServerResponse } from "http";

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

export const authorize = api.raw(
  { expose: true, method: "GET", path: "/oauth/authorize" },
  async (req: IncomingMessage, res: ServerResponse<IncomingMessage>): Promise<void> => {
    const parsedUrl = parse(req.url || "", true);
    const params = parsedUrl.query as unknown as AuthRequest;

    if (params.response_type !== "code") {
      throw APIError.invalidArgument("Unsupported response type");
    }
    const authCode = oauthService.generateAuthCode(params.client_id, params.redirect_uri, params.scope);
    const url = new URL(params.redirect_uri);
    url.searchParams.set("code", authCode.code);
    if (params.state) url.searchParams.set("state", params.state);

    res.writeHead(301, { Location: url.toString() });
    res.end();
  }
);
