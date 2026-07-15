import type { I18n } from "../i18n"
import type { SessionRecord, User } from "./domain"

/** Shared Hono generics: `Env` bindings plus per-request variables. */
export type AppVariables = {
  readonly requestId: string
  readonly i18n: I18n
  readonly session?: SessionRecord
  readonly user?: User
  /** Registered OAuth callback source allowed for the current consent form. */
  readonly oauthRedirectFormAction?: string
}

export type AppBindings = {
  readonly Bindings: Env
  readonly Variables: AppVariables
}
