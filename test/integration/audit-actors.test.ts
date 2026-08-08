import { createExecutionContext, env, SELF, waitOnExecutionContext } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { listAuditLogs } from "../../src/db/queries/audit"
import { createUser, getUserByEmail } from "../../src/db/queries/users"
import worker from "../../src/index"
import { insertAuditBatch } from "../../src/security/audit"

const ISSUER = "https://auth.pangda.app"

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM audit_logs WHERE id LIKE 'aud_actor_%'"),
    env.DB.prepare("DELETE FROM groups WHERE name = 'actor-console-group'"),
  ])
})

async function seedActorLogs(): Promise<{ adminId: string }> {
  const admin = await getUserByEmail(env, "admin")
  if (admin === null) throw new Error("seed administrator missing")
  await insertAuditBatch(env, [
    {
      id: "aud_actor_user",
      type: "admin.user.updated",
      actorUserId: admin.id,
      userId: "usr_actor_subject",
      success: true,
      createdAt: 2_000_000_001,
    },
    {
      id: "aud_actor_client",
      type: "oauth.client_credentials.issued",
      actorClientId: "svc_actor",
      clientId: "svc_actor",
      success: true,
      createdAt: 2_000_000_000,
    },
    {
      id: "aud_actor_resource_1",
      type: "admin.resource.updated",
      actorUserId: admin.id,
      resourceUri: "https://api.audit.example",
      scope: "api.read",
      requestId: "req-audit-resource",
      detail: "resource policy updated",
      success: true,
      createdAt: 2_000_000_003,
    },
    {
      id: "aud_actor_resource_2",
      type: "admin.resource.created",
      actorUserId: admin.id,
      resourceUri: "https://api.audit.example",
      success: true,
      createdAt: 2_000_000_002,
    },
  ])
  return { adminId: admin.id }
}

async function loginAdmin(): Promise<string> {
  const page = await SELF.fetch(`${ISSUER}/login`)
  const csrf =
    page.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("__Host-keyforge_csrf="))
      ?.split(";")[0]
      ?.split("=")[1] ?? ""
  const response = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({
      email: "admin",
      password: "test-admin-password-2026",
      csrf_token: csrf,
    }).toString(),
    redirect: "manual",
  })
  return (
    response.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("__Host-keyforge_session="))
      ?.split(";")[0] ?? ""
  )
}

describe("queryable audit actors", () => {
  it("stores and filters user and client actors with dedicated indexes", async () => {
    const { adminId } = await seedActorLogs()
    const byUser = await listAuditLogs(env, { limit: 10, offset: 0, actorUserId: adminId })
    expect(byUser).toHaveLength(3)
    expect(byUser.find((entry) => entry.id === "aud_actor_user")).toMatchObject({
      id: "aud_actor_user",
      actorUserId: adminId,
      actorClientId: null,
      userId: "usr_actor_subject",
    })
    const byClient = await listAuditLogs(env, {
      limit: 10,
      offset: 0,
      actorClientId: "svc_actor",
    })
    expect(byClient).toHaveLength(1)
    expect(byClient[0]).toMatchObject({
      id: "aud_actor_client",
      actorUserId: null,
      actorClientId: "svc_actor",
      clientId: "svc_actor",
    })
    const byResource = await listAuditLogs(env, {
      limit: 10,
      offset: 0,
      resourceUri: "https://api.audit.example",
    })
    expect(byResource.map((entry) => entry.id)).toEqual([
      "aud_actor_resource_1",
      "aud_actor_resource_2",
    ])

    for (const [column, index, value] of [
      ["actor_user_id", "idx_audit_actor_user_created", adminId],
      ["actor_client_id", "idx_audit_actor_client_created", "svc_actor"],
    ] as const) {
      const plan = await env.DB.prepare(
        `EXPLAIN QUERY PLAN SELECT id FROM audit_logs
         WHERE ${column} = ? ORDER BY created_at DESC LIMIT 10`,
      )
        .bind(value)
        .all<{ detail: string }>()
      expect(plan.results.map((row) => row.detail).join("\n")).toContain(index)
    }
  })

  it("exposes actor fields and filters only through authenticated admin surfaces", async () => {
    const { adminId } = await seedActorLogs()
    expect((await SELF.fetch(`${ISSUER}/admin/audit-logs`)).status).toBe(401)
    expect((await SELF.fetch(`${ISSUER}/console/audit`, { redirect: "manual" })).status).toBe(302)

    const sessionCookie = await loginAdmin()
    const api = await SELF.fetch(
      `${ISSUER}/admin/audit-logs?actor_user_id=${encodeURIComponent(adminId)}`,
      { headers: { cookie: sessionCookie } },
    )
    expect(api.status).toBe(200)
    const logs = await api.json<{
      logs: Array<Record<string, unknown>>
    }>()
    expect(logs.logs).toHaveLength(3)
    expect(logs.logs.find((entry) => entry["user_id"] === "usr_actor_subject")).toMatchObject({
      actor_user_id: adminId,
      actor_client_id: null,
      user_id: "usr_actor_subject",
    })

    const consolePage = await SELF.fetch(`${ISSUER}/console/audit?actor_client_id=svc_actor`, {
      headers: { cookie: sessionCookie },
    })
    expect(consolePage.status).toBe(200)
    const html = await consolePage.text()
    expect(html).toContain("Actor user")
    expect(html).toContain("Actor client")
    expect(html).toContain("svc_actor")
    expect(html).not.toContain("usr_actor_subject")
    const resourcePage = await SELF.fetch(
      `${ISSUER}/console/audit?resource_uri=${encodeURIComponent("https://api.audit.example")}&limit=1`,
      { headers: { cookie: sessionCookie } },
    )
    const resourceHtml = await resourcePage.text()
    expect(resourceHtml).toContain('name="resource_uri" value="https://api.audit.example"')
    expect(resourceHtml).toContain("/console/resources/https%3A%2F%2Fapi.audit.example")
    expect(resourceHtml).toContain("api.read")
    expect(resourceHtml).toContain("req-audit-resource")
    expect(resourceHtml).toContain(
      "resource_uri=https%3A%2F%2Fapi.audit.example&amp;limit=1&amp;offset=1",
    )
  })

  it("emits the authenticated administrator separately from the mutated user", async () => {
    const admin = await getUserByEmail(env, "admin")
    if (admin === null) throw new Error("seed administrator missing")
    const target = await createUser(env, { email: "actor-callsite-target@pangda.app" })
    const queued: unknown[] = []
    const isolatedEnv = new Proxy(env, {
      get(targetEnv, property, receiver) {
        if (property === "AUDIT_QUEUE") {
          return { send: async (message: unknown) => queued.push(message) } as unknown as Queue
        }
        return Reflect.get(targetEnv, property, receiver)
      },
    })
    const context = createExecutionContext()
    const response = await worker.fetch(
      new Request(`${ISSUER}/admin/users/${target.id}`, {
        method: "PATCH",
        headers: {
          cookie: await loginAdmin(),
          origin: ISSUER,
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
        },
        body: JSON.stringify({ name: "Updated by actor" }),
      }),
      isolatedEnv,
      context,
    )
    await waitOnExecutionContext(context)

    expect(response.status).toBe(200)
    expect(queued).toContainEqual(
      expect.objectContaining({
        type: "admin.user.updated",
        actorUserId: admin.id,
        actorClientId: undefined,
        userId: target.id,
      }),
    )
  })

  it("emits an actor for console mutations that have no user subject", async () => {
    const admin = await getUserByEmail(env, "admin")
    if (admin === null) throw new Error("seed administrator missing")
    const sessionCookie = await loginAdmin()
    const formPage = await SELF.fetch(`${ISSUER}/console/groups/new`, {
      headers: { cookie: sessionCookie },
    })
    const csrf =
      formPage.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith("__Host-keyforge_csrf="))
        ?.split(";")[0]
        ?.split("=")[1] ?? ""
    const queued: unknown[] = []
    const isolatedEnv = new Proxy(env, {
      get(targetEnv, property, receiver) {
        if (property === "AUDIT_QUEUE") {
          return { send: async (message: unknown) => queued.push(message) } as unknown as Queue
        }
        return Reflect.get(targetEnv, property, receiver)
      },
    })
    const context = createExecutionContext()
    const response = await worker.fetch(
      new Request(`${ISSUER}/console/groups`, {
        method: "POST",
        headers: {
          cookie: `${sessionCookie}; __Host-keyforge_csrf=${csrf}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          csrf_token: csrf,
          name: "actor-console-group",
          description: "Actor attribution test",
        }).toString(),
      }),
      isolatedEnv,
      context,
    )
    await waitOnExecutionContext(context)

    expect(response.status).toBe(302)
    const audit = queued.find(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "type" in message &&
        message.type === "admin.group.created",
    )
    expect(audit).toMatchObject({
      type: "admin.group.created",
      actorUserId: admin.id,
    })
    expect(audit).not.toHaveProperty("userId")
  })
})
