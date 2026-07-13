import type { Context } from "hono"
import type { AppBindings } from "../types/app"

export function extractBearerToken(c: Context<AppBindings>): string | null {
  const header = c.req.header("authorization")
  if (header === undefined || !/^Bearer /i.test(header)) {
    return null
  }
  const token = header.slice(7).trim()
  return token === "" ? null : token
}
