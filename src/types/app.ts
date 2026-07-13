import type { SessionRecord, User } from "./domain"

/** Shared Hono generics: `Env` bindings plus per-request variables. */
export type AppVariables = {
  readonly requestId: string
  readonly session?: SessionRecord
  readonly user?: User
}

export type AppBindings = {
  readonly Bindings: Env
  readonly Variables: AppVariables
}
