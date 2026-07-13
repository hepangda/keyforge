import { afterEach, describe, expect, it, vi } from "vitest"
import { deliverQueuedEmail, enqueueEmail } from "../../src/email/sender"

function remoteEmailEnv(send: ReturnType<typeof vi.fn>) {
  return {
    ENVIRONMENT: "production",
    EMAIL_DELIVERY_MODE: "resend",
    EMAIL_FROM: "KeyForge <auth@pangda.app>",
    RESEND_API_KEY: "re_test_key_long_enough",
    KV: {} as KVNamespace,
    EMAIL_QUEUE: { send } as unknown as Queue,
  } as const
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("transactional email queue", () => {
  it("enqueues remote delivery and reuses the job id as the provider idempotency key", async () => {
    const send = vi.fn().mockResolvedValue(undefined)
    const env = remoteEmailEnv(send)
    await enqueueEmail(env, {
      to: "person@example.com",
      subject: "Sign in",
      html: "<p>Use the secure link.</p>",
      text: "Use the secure link.",
    })

    expect(send).toHaveBeenCalledOnce()
    const job = send.mock.calls[0]?.[0]
    expect(job).toMatchObject({ kind: "transactional_email", to: "person@example.com" })
    expect(job.id).toMatch(/^[0-9a-f-]{36}$/)

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }))
    vi.stubGlobal("fetch", fetchMock)
    await deliverQueuedEmail(env, job)
    const request = fetchMock.mock.calls[0]
    expect(request?.[0]).toBe("https://api.resend.com/emails")
    expect(request?.[1]?.headers).toMatchObject({ "idempotency-key": job.id })
  })

  it("rejects malformed queue jobs so Queues can retry and dead-letter them", async () => {
    const env = remoteEmailEnv(vi.fn())
    await expect(
      deliverQueuedEmail(env, {
        kind: "transactional_email",
        id: "not-a-uuid",
        to: "invalid",
      }),
    ).rejects.toBeDefined()
  })
})
