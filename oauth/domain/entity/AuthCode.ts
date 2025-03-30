export class AuthCode {
  constructor(
    public readonly code: string,
    public readonly clientId: string,
    public readonly userId: string,
    public readonly scope?: string
  ) {}
}