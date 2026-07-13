import type { Context } from "hono"
import type { AppBindings } from "../types/app"

const DEFAULT_LIMIT = 50
const MAX_LIMIT = 200

export type Pagination = { readonly limit: number; readonly offset: number }

export function parsePagination(c: Context<AppBindings>): Pagination {
  const rawLimit = Number(c.req.query("limit") ?? DEFAULT_LIMIT)
  const rawOffset = Number(c.req.query("offset") ?? 0)
  const limit = Number.isFinite(rawLimit)
    ? Math.min(Math.max(Math.trunc(rawLimit), 1), MAX_LIMIT)
    : DEFAULT_LIMIT
  const offset = Number.isFinite(rawOffset) ? Math.max(Math.trunc(rawOffset), 0) : 0
  return { limit, offset }
}

/** Parse a JSON request body, returning null on any parse/read failure. */
export async function readJsonBody(c: Context<AppBindings>): Promise<unknown> {
  try {
    return await c.req.json()
  } catch (error) {
    if (error instanceof Error) {
      return null
    }
    throw error
  }
}
