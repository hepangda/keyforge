// PKCE Authorization Code helper. The SPA is registered with keyforge as a
// public client (no secret); every login uses S256 PKCE per OAuth 2.1.
//
// State + verifier are persisted to sessionStorage so a navigation /refresh
// during the IdP redirect doesn't lose them.

const ISSUER = window.location.origin
const CLIENT_ID = 'keyforge-spa'
const SCOPES = ['openid', 'profile', 'email', 'offline_access', 'kf:portal']

const STORAGE_KEY = 'kf.pkce'

interface PendingFlow {
  state: string
  nonce: string
  verifier: string
  returnTo: string
}

interface TokenSet {
  access_token: string
  refresh_token?: string
  id_token?: string
  token_type: string
  expires_in: number
  scope?: string
  obtained_at: number
}

const ACTIVE_KEY = 'kf.tokens'

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len)
  crypto.getRandomValues(out)
  return out
}

function base64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function sha256(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return base64url(digest)
}

function newRandomToken(len = 32): string {
  return base64url(randomBytes(len))
}

export interface OidcConfig {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
  userinfo_endpoint?: string
}

let discoveryCache: OidcConfig | null = null

export async function discovery(): Promise<OidcConfig> {
  if (discoveryCache) return discoveryCache
  const resp = await fetch(`${ISSUER}/.well-known/openid-configuration`)
  if (!resp.ok) throw new Error(`discovery: ${resp.status}`)
  discoveryCache = await resp.json()
  return discoveryCache!
}

export async function beginLogin(returnTo: string): Promise<void> {
  const cfg = await discovery()
  const verifier = newRandomToken(32)
  const state = newRandomToken(24)
  const nonce = newRandomToken(24)
  const pending: PendingFlow = { state, nonce, verifier, returnTo }
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(pending))

  const challenge = await sha256(verifier)
  const url = new URL(cfg.authorization_endpoint)
  url.searchParams.set('client_id', CLIENT_ID)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('redirect_uri', `${ISSUER}/portal/callback`)
  url.searchParams.set('scope', SCOPES.join(' '))
  url.searchParams.set('state', state)
  url.searchParams.set('nonce', nonce)
  url.searchParams.set('code_challenge', challenge)
  url.searchParams.set('code_challenge_method', 'S256')
  window.location.assign(url.toString())
}

export async function completeLogin(currentURL: string): Promise<string> {
  const url = new URL(currentURL)
  const err = url.searchParams.get('error')
  if (err) throw new Error(`upstream error: ${err}`)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  if (!code || !state) throw new Error('missing code or state on callback')
  const rawPending = sessionStorage.getItem(STORAGE_KEY)
  if (!rawPending) throw new Error('no pending PKCE state')
  const pending = JSON.parse(rawPending) as PendingFlow
  if (pending.state !== state) throw new Error('state mismatch')
  sessionStorage.removeItem(STORAGE_KEY)

  const cfg = await discovery()
  const body = new URLSearchParams()
  body.set('grant_type', 'authorization_code')
  body.set('client_id', CLIENT_ID)
  body.set('code', code)
  body.set('redirect_uri', `${ISSUER}/portal/callback`)
  body.set('code_verifier', pending.verifier)
  const resp = await fetch(cfg.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`token exchange: ${resp.status} ${text}`)
  }
  const tokens = (await resp.json()) as TokenSet
  tokens.obtained_at = Date.now()
  sessionStorage.setItem(ACTIVE_KEY, JSON.stringify(tokens))
  return pending.returnTo
}

export function loadTokens(): TokenSet | null {
  const raw = sessionStorage.getItem(ACTIVE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as TokenSet
  } catch {
    return null
  }
}

export function clearTokens(): void {
  sessionStorage.removeItem(ACTIVE_KEY)
}

export function bearer(): string | null {
  const t = loadTokens()
  if (!t) return null
  const age = (Date.now() - t.obtained_at) / 1000
  if (age >= t.expires_in - 30) return null
  return t.access_token
}

export async function refresh(): Promise<TokenSet | null> {
  const current = loadTokens()
  if (!current?.refresh_token) return null
  const cfg = await discovery()
  const body = new URLSearchParams()
  body.set('grant_type', 'refresh_token')
  body.set('client_id', CLIENT_ID)
  body.set('refresh_token', current.refresh_token)
  const resp = await fetch(cfg.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (!resp.ok) {
    clearTokens()
    return null
  }
  const fresh = (await resp.json()) as TokenSet
  fresh.obtained_at = Date.now()
  sessionStorage.setItem(ACTIVE_KEY, JSON.stringify(fresh))
  return fresh
}
