export type TokenResponse = {
  access_token: string
  token_type: "Bearer"
  expires_in: number
  scope: string
  id_token?: string
  refresh_token?: string
}
