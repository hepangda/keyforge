import { AppError } from "../security/errors"

export type FetchJsonInit = {
  readonly method?: string
  readonly headers?: Record<string, string>
  readonly body?: string
  readonly timeoutMs?: number
}

/**
 * Single-shot JSON fetch with a timeout and an ok-status check. No retry — used
 * for OAuth code exchange, where a retried single-use code would fail anyway.
 */
export async function fetchJson(url: string, init: FetchJsonInit = {}): Promise<unknown> {
  const requestInit: RequestInit = {
    method: init.method ?? "GET",
    signal: AbortSignal.timeout(init.timeoutMs ?? 8000),
  }
  if (init.headers !== undefined) {
    requestInit.headers = init.headers
  }
  if (init.body !== undefined) {
    requestInit.body = init.body
  }
  const response = await fetch(url, requestInit)
  if (!response.ok) {
    throw new AppError(502, "Upstream request failed", {
      detail: `${url} responded with ${response.status}`,
    })
  }
  return response.json()
}
