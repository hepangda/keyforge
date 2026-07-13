import { z } from "zod"
import { AppError } from "../security/errors"
import type { EmailContent } from "./templates"

export type EmailMessage = EmailContent & { readonly to: string }

type EmailEnv = Pick<
  Env,
  "ENVIRONMENT" | "EMAIL_DELIVERY_MODE" | "EMAIL_FROM" | "RESEND_API_KEY" | "KV"
>

type EmailQueueEnv = EmailEnv & Pick<Env, "EMAIL_QUEUE">

const queuedEmailSchema = z.object({
  kind: z.literal("transactional_email"),
  id: z.uuid(),
  to: z.email().max(254),
  subject: z.string().min(1).max(998),
  html: z.string().min(1).max(100_000),
  text: z.string().min(1).max(50_000),
})

export type QueuedEmailMessage = z.infer<typeof queuedEmailSchema>

function requireResendConfiguration(env: EmailEnv): void {
  if (env.EMAIL_DELIVERY_MODE !== "resend" || !env.RESEND_API_KEY || !env.EMAIL_FROM) {
    throw new AppError(503, "Email delivery is unavailable", {
      detail: "production email requires EMAIL_DELIVERY_MODE=resend, EMAIL_FROM and RESEND_API_KEY",
    })
  }
}

/**
 * Accept a transactional email for delivery. Remote environments enqueue a
 * stable, idempotent job so transient provider failures are retried by Queues
 * and eventually isolated in the configured DLQ. Local/test delivery remains
 * synchronous so developer feedback and integration tests stay deterministic.
 */
export async function enqueueEmail(env: EmailQueueEnv, message: EmailMessage): Promise<void> {
  if (env.EMAIL_DELIVERY_MODE !== "resend") {
    await sendEmail(env, message)
    return
  }
  requireResendConfiguration(env)
  const job: QueuedEmailMessage = {
    kind: "transactional_email",
    id: crypto.randomUUID(),
    ...message,
  }
  await env.EMAIL_QUEUE.send(job)
}

export function isQueuedEmailMessage(value: unknown): value is QueuedEmailMessage {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    value.kind === "transactional_email"
  )
}

/** Queue consumer entry point. Throws on malformed jobs or provider failure. */
export async function deliverQueuedEmail(env: EmailEnv, raw: unknown): Promise<void> {
  const message = queuedEmailSchema.parse(raw)
  await sendEmail(env, message, message.id)
}

/** Deliver transactional email. Production is fail-closed unless Resend is configured. */
export async function sendEmail(
  env: EmailEnv,
  message: EmailMessage,
  idempotencyKey = crypto.randomUUID(),
): Promise<void> {
  if (env.EMAIL_DELIVERY_MODE === "test") {
    await env.KV.put(`test:email:${message.to.toLowerCase()}`, JSON.stringify(message), {
      expirationTtl: 3600,
    })
    return
  }
  if (env.EMAIL_DELIVERY_MODE === "console" && env.ENVIRONMENT !== "production") {
    console.log("email.preview", message.to, message.subject, message.text)
    return
  }
  requireResendConfiguration(env)

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify({
      from: env.EMAIL_FROM,
      to: [message.to],
      subject: message.subject,
      html: message.html,
      text: message.text,
    }),
    signal: AbortSignal.timeout(8000),
  })
  if (!response.ok) {
    throw new AppError(502, "Email delivery failed", {
      detail: `Resend responded with ${response.status}`,
    })
  }
}
