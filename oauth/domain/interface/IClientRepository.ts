import { Client } from "../entity/Client";

export interface IClientRepository {
  getById(clientId: string): Client | undefined;
}
