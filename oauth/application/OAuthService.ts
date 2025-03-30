// application/OAuthService.ts
import { v4 as uuid } from "uuid";
import jwt from "jsonwebtoken";
import { AuthCode } from "../domain/entity/AuthCode";
import { Token } from "../domain/entity/Token";
import { IClientRepository } from "../domain/interface/IClientRepository";
import { IAuthCodeRepository } from "../domain/interface/IAuthCodeRepository";
import { ITokenRepository } from "../domain/interface/ITokenRepository";

const issuer = "http://localhost:3000"; // Update as needed
const signingKey = "your-very-secure-secret"; // Secure this key

export class OAuthService {
  constructor(private clientRepo: IClientRepository, private authCodeRepo: IAuthCodeRepository, private tokenRepo: ITokenRepository) {}

  generateAuthCode(clientId: string, redirectUri: string, scope?: string): AuthCode {
    const client = this.clientRepo.getById(clientId);
    if (!client || client.redirectUri !== redirectUri) {
      throw new Error("Invalid client");
    }
    const code = uuid();
    const authCode = new AuthCode(code, clientId, "user-123", scope);
    this.authCodeRepo.save(authCode);
    return authCode;
  }

  exchangeAuthCodeForToken(
    clientId: string,
    clientSecret: string,
    redirectUri: string,
    code: string
  ): { token: Token; refreshToken: string; idToken: string } {
    const client = this.clientRepo.getById(clientId);
    if (!client || !client.validate(clientId, clientSecret, redirectUri)) {
      throw new Error("Invalid client credentials");
    }
    const authCode = this.authCodeRepo.getByCode(code);
    if (!authCode || authCode.clientId !== clientId) {
      throw new Error("Invalid or expired auth code");
    }
    // One-time use: invalidate the auth code.
    this.authCodeRepo.delete(code);

    const accessToken = uuid();
    const token = new Token(accessToken, authCode.userId, authCode.scope);
    this.tokenRepo.save(token);

    const refreshToken = uuid();
    this.tokenRepo.saveRefreshToken(refreshToken, token);

    const now = Math.floor(Date.now() / 1000);
    const idToken = jwt.sign(
      {
        sub: authCode.userId,
        aud: clientId,
        iss: issuer,
        exp: now + token.expiresIn,
        iat: now,
        scope: authCode.scope,
      },
      signingKey
    );
    return { token, refreshToken, idToken };
  }

  refreshToken(clientId: string, clientSecret: string, refreshToken: string): { token: Token; newRefreshToken: string; idToken: string } {
    const client = this.clientRepo.getById(clientId);
    if (!client || client.secret !== clientSecret) {
      throw new Error("Invalid client credentials");
    }
    const token = this.tokenRepo.getTokenByRefreshToken(refreshToken);
    if (!token) {
      throw new Error("Invalid refresh token");
    }
    // Invalidate the old refresh token.
    this.tokenRepo.deleteRefreshToken(refreshToken);

    const newAccessToken = uuid();
    const newToken = new Token(newAccessToken, token.userId, token.scope);
    this.tokenRepo.save(newToken);

    const newRefreshToken = uuid();
    this.tokenRepo.saveRefreshToken(newRefreshToken, newToken);

    const now = Math.floor(Date.now() / 1000);
    const idToken = jwt.sign(
      {
        sub: token.userId,
        aud: clientId,
        iss: issuer,
        exp: now + newToken.expiresIn,
        iat: now,
        scope: token.scope,
      },
      signingKey
    );
    return { token: newToken, newRefreshToken, idToken };
  }

  getUserInfo(accessToken: string): { userId: string; scope?: string } {
    const token = this.tokenRepo.getByAccessToken(accessToken);
    if (!token) {
      throw new Error("Invalid token");
    }
    return { userId: token.userId, scope: token.scope };
  }
}
