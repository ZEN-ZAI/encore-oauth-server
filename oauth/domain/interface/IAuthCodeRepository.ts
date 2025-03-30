import { AuthCode } from "../entity/AuthCode";

export interface IAuthCodeRepository {
  save(authCode: AuthCode): void;
  getByCode(code: string): AuthCode | undefined;
  delete(code: string): void;
}
