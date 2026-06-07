// Admin API response shapes.
export interface AdminUser {
  id: string
  email: string
  email_verified: boolean
  display_name: string
  enabled: boolean
  created_at: string
}

export interface AdminRole {
  id: string
  name: string
  description: string
  permissions: string[]
}

export interface AdminClient {
  id: string
  client_id: string
  name: string
  description?: string
  client_type: string
  grant_types: string[]
  scopes: string[]
  redirect_uris: string[]
  token_endpoint_auth_method: string
  require_par: boolean
  require_dpop: boolean
  dpop_bound_access_tokens: boolean
  tls_client_certificate_bound_access_tokens: boolean
}

export interface AuditRow {
  id: number
  action: string
  target_type: string
  target_id: string
  actor_user_id: string
  actor_client_id: string
  ip: string
  user_agent: string
  request_id: string
  attributes: Record<string, unknown>
  occurred_at: string
}

export interface AdminSession {
  id: string
  ip: string
  user_agent: string
  mfa_level: string
  amr: string[]
  auth_time: string
  last_seen_at: string
  expires_at: string
}
