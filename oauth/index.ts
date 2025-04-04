import { api } from "encore.dev/api";

interface IndexResponse {
  message: string;
}

export const index = api({ method: "GET", expose: true, path: "/" }, async (): Promise<IndexResponse> => {
  return { message: "Welcome to the OAuth Server API!" };
});
