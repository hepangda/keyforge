// Thin fetch wrapper that injects the bearer token and refreshes once on 401.

import { bearer, clearTokens, refresh } from '../auth/oidc'

export interface ApiError extends Error {
  status: number
  body?: unknown
}

async function call(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const headers = new Headers(init.headers ?? {})
  const token = bearer()
  if (token) headers.set('authorization', `Bearer ${token}`)
  if (!headers.has('accept')) headers.set('accept', 'application/json')
  const resp = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  if (resp.status === 401 && retry) {
    const r = await refresh()
    if (r) return call(path, init, false)
    clearTokens()
  }
  return resp
}

export async function get<T>(path: string): Promise<T> {
  const resp = await call(path)
  if (!resp.ok) throw await asError(resp)
  return (await resp.json()) as T
}

export async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const resp = await call(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!resp.ok) throw await asError(resp)
  if (resp.status === 204) return undefined as T
  return (await resp.json()) as T
}

export async function del(path: string): Promise<void> {
  const resp = await call(path, { method: 'DELETE' })
  if (!resp.ok) throw await asError(resp)
}

async function asError(resp: Response): Promise<ApiError> {
  let body: unknown
  try {
    body = await resp.json()
  } catch {
    body = await resp.text().catch(() => undefined)
  }
  const err = new Error(`api error ${resp.status}`) as ApiError
  err.status = resp.status
  err.body = body
  return err
}
