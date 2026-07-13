// Social provider credentials are secrets (client_id is public but kept here for
// symmetry). Set via `wrangler secret put` / `[vars]`; they are optional so the
// server runs without social login configured.
declare global {
  interface Env {
    readonly GITHUB_CLIENT_ID?: string
    readonly GITHUB_CLIENT_SECRET?: string
    readonly GOOGLE_CLIENT_ID?: string
    readonly GOOGLE_CLIENT_SECRET?: string
    readonly RESEND_API_KEY?: string
    readonly REQUEST_HASH_SECRET?: string
    readonly READINESS_PROBE_TOKEN?: string
    readonly BOOTSTRAP_TOKEN?: string
    readonly EMAIL_DELIVERY_MODE: "resend" | "console" | "test"
    readonly EMAIL_FROM?: string
  }
}

export {}
