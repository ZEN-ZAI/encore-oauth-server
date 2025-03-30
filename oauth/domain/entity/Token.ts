export class Token {
  constructor(
    public readonly accessToken: string,
    public readonly userId: string,
    public readonly scope?: string,
    public readonly expiresIn: number = 3600
  ) {}
}