declare global {
  interface Env {
    readonly RESEND_API_KEY?: string
    readonly REQUEST_HASH_SECRET?: string
    readonly READINESS_PROBE_TOKEN?: string
    readonly BOOTSTRAP_TOKEN?: string
    readonly EMAIL_DELIVERY_MODE: "resend" | "console" | "test"
    readonly EMAIL_FROM?: string
  }
}

export {}
