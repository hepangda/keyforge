// Domain models for portal API responses.
export interface UserProfile {
  id: string
  email: string
  email_verified: boolean
  display_name: string
  locale: string
  zoneinfo: string
  picture_url: string
  created_at: string
  updated_at: string
}

export interface SessionRow {
  id: string
  ip: string
  user_agent: string
  mfa_level: string
  amr: string[]
  auth_time: string
  last_seen_at: string
  expires_at: string
}

export interface ConsentRow {
  id: string
  client_id: string
  scopes: string[]
  granted_at: string
}

export interface MFAStatus {
  totp: boolean
  webauthn: boolean
  recovery_codes_remaining: number
}

export interface TOTPEnrollBeginResp {
  otpauth_url: string
  secret: string
}

export interface RecoveryCodesResp {
  codes: string[]
}
