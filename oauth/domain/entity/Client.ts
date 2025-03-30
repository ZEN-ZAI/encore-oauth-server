export class Client {
  constructor(
    public readonly id: string,
    public readonly secret: string,
    public readonly redirectUri: string
  ) {}

  validate(clientId: string, clientSecret: string, redirectUri: string): boolean {
    return this.id === clientId && this.secret === clientSecret && this.redirectUri === redirectUri;
  }
}