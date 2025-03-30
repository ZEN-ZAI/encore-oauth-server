// store.ts

export const clients = [
  {
    clientId: "client-id-123",
    clientSecret: "secret-abc",
    redirectUri: "http://localhost:3000/callback",
  },
];

export const authCodes: Record<string, { clientId: string; userId: string; scope?: string }> = {};
export const tokens: Record<string, { accessToken: string; userId: string; scope?: string }> = {};
export const refreshTokens: Record<string, { refreshToken: string; clientId: string; userId: string; scope?: string }> = {};
