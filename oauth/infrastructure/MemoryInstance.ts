// infrastructure/repositories.ts
import { InMemoryClientRepository, InMemoryAuthCodeRepository, InMemoryTokenRepository } from "./MemoryRepository";

export const clientRepository = new InMemoryClientRepository();
export const authCodeRepository = new InMemoryAuthCodeRepository();
export const tokenRepository = new InMemoryTokenRepository();
