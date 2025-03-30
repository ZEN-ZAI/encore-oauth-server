// infrastructure/MemoryRepository.ts
import { IClientRepository } from "../domain/interface/IClientRepository";
import { Client } from "../domain/entity/Client";
import { IAuthCodeRepository } from "../domain/interface/IAuthCodeRepository";
import { AuthCode } from "../domain/entity/AuthCode";
import { ITokenRepository } from "../domain/interface/ITokenRepository";
import { Token } from "../domain/entity/Token";

export class InMemoryClientRepository implements IClientRepository {
  private clients: Map<string, Client> = new Map();
  constructor() {
    // Preload a demo client
    this.clients.set("client-id-123", new Client("client-id-123", "secret-abc", "http://localhost:3000/callback"));
  }
  getById(clientId: string): Client | undefined {
    return this.clients.get(clientId);
  }
}

export class InMemoryAuthCodeRepository implements IAuthCodeRepository {
  private authCodes: Map<string, AuthCode> = new Map();
  save(authCode: AuthCode): void {
    this.authCodes.set(authCode.code, authCode);
  }
  getByCode(code: string): AuthCode | undefined {
    return this.authCodes.get(code);
  }
  delete(code: string): void {
    this.authCodes.delete(code);
  }
}

export class InMemoryTokenRepository implements ITokenRepository {
  private tokens: Map<string, Token> = new Map();
  private refreshTokens: Map<string, Token> = new Map();
  save(token: Token): void {
    this.tokens.set(token.accessToken, token);
  }
  getByAccessToken(accessToken: string): Token | undefined {
    return this.tokens.get(accessToken);
  }
  saveRefreshToken(refreshToken: string, token: Token): void {
    this.refreshTokens.set(refreshToken, token);
  }
  getTokenByRefreshToken(refreshToken: string): Token | undefined {
    return this.refreshTokens.get(refreshToken);
  }
  deleteRefreshToken(refreshToken: string): void {
    this.refreshTokens.delete(refreshToken);
  }
}
