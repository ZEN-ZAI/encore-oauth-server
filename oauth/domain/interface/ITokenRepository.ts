import { Token } from "../entity/Token";

export interface ITokenRepository {
  save(token: Token): void;
  getByAccessToken(accessToken: string): Token | undefined;
  saveRefreshToken(refreshToken: string, token: Token): void;
  getTokenByRefreshToken(refreshToken: string): Token | undefined;
  deleteRefreshToken(refreshToken: string): void;
}
