import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { verifyUserPassword } from "../../src/auth/password"
import { createSession } from "../../src/auth/session"
import {
  createUser,
  getGroupByName,
  getUserByEmail,
  getUserById,
  getUserGroupNames,
  getUserSecurityVersion,
  setUserGroupsPreservingActiveAdmin,
  updateUser,
} from "../../src/db/queries/users"
import { evaluateUserTokenAccess } from "../../src/oauth/user-token-policy"
import { issueRefreshToken } from "../../src/tokens/refresh-token"

const ISSUER = "https://auth.pangda.app"

let adminCookie = ""
let adminUserId = ""
let userCookie = ""
let regularUserId = ""
let regularSessionId = ""

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM refresh_tokens"),
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM device_authorization_sessions"),
    env.DB.prepare("DELETE FROM users"),
    env.DB.prepare("DELETE FROM groups WHERE name LIKE 'test-%'"),
    env.DB.prepare("DELETE FROM oauth_clients WHERE client_id LIKE 'test_%'"),
    env.DB.prepare("DELETE FROM oauth_resources WHERE resource_uri LIKE 'urn:test:%'"),
  ])
  const adminUser = await createUser(env, {
    email: "admin@pangda.app",
    name: "Admin",
  })
  adminUserId = adminUser.id
  await env.DB.prepare(
    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_admins', unixepoch())",
  )
    .bind(adminUser.id)
    .run()
  adminCookie = `__Host-keyforge_session=${(await createSession(env, { userId: adminUser.id, authMethod: "password", ttlSeconds: 3600 })).token}`

  const regularUser = await createUser(env, {
    email: "user@pangda.app",
    name: "User",
  })
  regularUserId = regularUser.id
  const regularSession = await createSession(env, {
    userId: regularUser.id,
    authMethod: "password",
    ttlSeconds: 3600,
  })
  regularSessionId = regularSession.sessionId
  userCookie = `__Host-keyforge_session=${regularSession.token}`
})

function req(method: string, path: string, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { cookie: adminCookie }
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["origin"] = ISSUER
    headers["sec-fetch-site"] = "same-origin"
  }
  if (body !== undefined) {
    headers["content-type"] = "application/json"
    return SELF.fetch(`${ISSUER}${path}`, {
      method,
      headers,
      body: JSON.stringify(body),
      redirect: "manual",
    })
  }
  return SELF.fetch(`${ISSUER}${path}`, { method, headers, redirect: "manual" })
}

describe("admin API access control", () => {
  it("requires an authenticated session", async () => {
    expect((await SELF.fetch(`${ISSUER}/admin/users`)).status).toBe(401)
  })

  it("forbids non-admins", async () => {
    expect(
      (await SELF.fetch(`${ISSUER}/admin/users`, { headers: { cookie: userCookie } })).status,
    ).toBe(403)
  })
})

describe("admin users", () => {
  it("lists, gets, patches, and revokes sessions", async () => {
    const list = await req("GET", "/admin/users")
    expect(list.status).toBe(200)
    expect((await list.json<{ users: unknown[] }>()).users.length).toBeGreaterThanOrEqual(2)

    const detail = await req("GET", `/admin/users/${regularUserId}`)
    const detailBody = await detail.json<Record<string, unknown>>()
    expect(detailBody["email"]).toBe("user@pangda.app")
    expect(detailBody["alias"]).toEqual(expect.any(String))
    expect(detailBody).not.toHaveProperty("user_type")

    const refresh = await issueRefreshToken(env, {
      userId: regularUserId,
      clientId: "pangda_app",
      sessionId: regularSessionId,
      resource: "https://api.pangda.app",
      scope: "openid profile email offline_access api.read",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })

    const patch = await req("PATCH", `/admin/users/${regularUserId}`, { disabled: true })
    expect((await patch.json<{ disabled: boolean }>()).disabled).toBe(true)

    expect((await req("POST", `/admin/users/${regularUserId}/revoke-sessions`)).status).toBe(200)
    const family = await env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId).getState()
    expect(family?.revoked).toBe(true)
    const mirror = await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
      .bind(refresh.familyId)
      .first<{ revoked_at: number | null }>()
    expect(mirror?.revoked_at).not.toBeNull()
    const check = await SELF.fetch(`${ISSUER}/`, {
      headers: { cookie: userCookie },
      redirect: "manual",
    })
    expect(check.status).toBe(302)
  })

  it("creates password users and assigns validated groups", async () => {
    const employees = await getGroupByName(env, "employees")
    expect(employees).not.toBeNull()
    const created = await req("POST", "/admin/users", {
      email: "new.user@pangda.app",
      alias: "new-user_1",
      name: "New User",
      email_verified: true,
      password: "a long initial password",
      group_ids: [employees?.id],
    })
    expect(created.status).toBe(201)
    const body = await created.json<{
      id: string
      groups: string[]
      credential_setup: string
    }>()
    expect(body.credential_setup).toBe("password_set")
    expect(body.groups).toEqual(["employees"])
    expect(await verifyUserPassword(env, body.id, "a long initial password")).toBe(true)
    expect((await getUserByEmail(env, "new.user@pangda.app"))?.alias).toBe("new-user_1")
  })

  it("sends a single-use invitation when no initial password is supplied", async () => {
    await env.KV.delete("test:email:invitee@pangda.app")
    const created = await req("POST", "/admin/users", {
      email: "invitee@pangda.app",
      alias: "invitee",
      email_verified: false,
      group_ids: [],
    })
    expect(created.status).toBe(201)
    const responseText = await created.text()
    expect(responseText).toContain('"credential_setup":"invitation_sent"')
    expect(responseText).not.toContain("/password/reset?token=")

    const delivery = await env.KV.get<{ subject: string; text: string }>(
      "test:email:invitee@pangda.app",
      "json",
    )
    expect(delivery?.subject).toContain("invited")
    expect(delivery?.text).toContain("/password/reset?token=")
    expect(await getUserByEmail(env, "invitee@pangda.app")).not.toBeNull()
  })

  it("manages password login methods and generates a magic link on demand", async () => {
    const password = await req("POST", `/admin/users/${regularUserId}/passwords`, {
      password: "sixsix",
      name: "Temporary access",
    })
    expect(password.status).toBe(201)

    const methods = await req("GET", `/admin/users/${regularUserId}/login-methods`)
    expect(methods.status).toBe(200)
    expect((await methods.json<{ passwords: Array<{ name: string }> }>()).passwords).toContainEqual(
      expect.objectContaining({ name: "Temporary access" }),
    )

    const generated = await req("POST", `/admin/users/${regularUserId}/magic-link`)
    expect(generated.status).toBe(200)
    const body = await generated.json<{ url: string; expires_in: number }>()
    expect(body.expires_in).toBe(15 * 60)
    expect(body.url).toContain("/login/magic/callback?token=")
    const confirmation = await SELF.fetch(body.url)
    expect(confirmation.status).toBe(200)
    expect(await confirmation.text()).toContain("Confirm sign in")
  }, 10_000)

  it("lets an administrator change a username without changing the stable user id", async () => {
    const response = await req("PATCH", `/admin/users/${regularUserId}`, {
      alias: "renamed-user_2",
    })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual(
      expect.objectContaining({ id: regularUserId, alias: "renamed-user_2" }),
    )
    expect((await getUserById(env, regularUserId))?.alias).toBe("renamed-user_2")

    const admin = await getUserById(env, adminUserId)
    const duplicate = await req("PATCH", `/admin/users/${regularUserId}`, {
      alias: admin?.alias,
    })
    expect(duplicate.status).toBe(409)
    expect(await duplicate.json()).toEqual({ error: "duplicate_alias" })
    expect((await getUserById(env, regularUserId))?.alias).toBe("renamed-user_2")

    const invalid = await req("PATCH", `/admin/users/${regularUserId}`, {
      alias: "not.valid",
    })
    expect(invalid.status).toBe(400)
  })

  it("creates groups and rejects unknown group assignments", async () => {
    const created = await req("POST", "/admin/groups", {
      name: "test-support",
      description: "Support operators",
    })
    expect(created.status).toBe(201)
    const group = await created.json<{ id: string; name: string }>()
    expect(group.name).toBe("test-support")

    const assigned = await req("PUT", `/admin/users/${regularUserId}/groups`, {
      group_ids: [group.id],
    })
    expect(assigned.status).toBe(200)
    expect(await getUserGroupNames(env, regularUserId)).toEqual(["test-support"])

    expect(
      (await req("PUT", `/admin/users/${regularUserId}/groups`, { group_ids: ["missing"] })).status,
    ).toBe(400)
  })

  it("does not disable or demote the last active administrator", async () => {
    const disable = await req("PATCH", `/admin/users/${adminUserId}`, { disabled: true })
    expect(disable.status).toBe(409)
    expect(await disable.json()).toEqual({ error: "last_active_admin" })

    const demote = await req("PUT", `/admin/users/${adminUserId}/groups`, { group_ids: [] })
    expect(demote.status).toBe(409)
    expect(await demote.json()).toEqual({ error: "last_active_admin" })
    expect(await getUserGroupNames(env, adminUserId)).toContain("admins")
  })

  it("preserves one active administrator under concurrent disable attempts", async () => {
    const second = await createUser(env, {
      email: "second.admin@pangda.app",
      name: "Second Admin",
    })
    await env.DB.prepare(
      "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_admins', unixepoch())",
    )
      .bind(second.id)
      .run()

    const results = await Promise.all([
      updateUser(env, adminUserId, { disabled: true }),
      updateUser(env, second.id, { disabled: true }),
    ])
    expect(results.filter((result) => result !== null)).toHaveLength(1)
    const active = await env.DB.prepare(
      `SELECT COUNT(*) AS count FROM users u
       JOIN user_groups ug ON ug.user_id = u.id
       WHERE ug.group_id = 'grp_seed_admins' AND u.disabled = 0`,
    ).first<{ count: number }>()
    expect(active?.count).toBe(1)
  })

  it("rolls back an administrative disable and every D1 revocation mirror together", async () => {
    const securityVersion = await getUserSecurityVersion(env, regularUserId)
    const refresh = await issueRefreshToken(env, {
      userId: regularUserId,
      clientId: "pangda_app",
      sessionId: regularSessionId,
      resource: "https://api.pangda.app",
      scope: "openid offline_access",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })
    await env.DB.prepare(
      `CREATE TRIGGER fail_atomic_admin_refresh
       BEFORE UPDATE OF revoked_at ON refresh_tokens
       BEGIN SELECT RAISE(ABORT, 'simulated refresh mirror failure'); END`,
    ).run()

    try {
      await expect(updateUser(env, regularUserId, { disabled: true })).rejects.toThrow()
    } finally {
      await env.DB.prepare("DROP TRIGGER IF EXISTS fail_atomic_admin_refresh").run()
    }

    expect((await getUserByEmail(env, "user@pangda.app"))?.disabled).toBe(false)
    expect(await getUserSecurityVersion(env, regularUserId)).toBe(securityVersion)
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM sessions WHERE id = ?")
          .bind(regularSessionId)
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).toBeNull()
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
          .bind(refresh.familyId)
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).toBeNull()
    expect((await env.REFRESH_TOKEN_FAMILY.getByName(refresh.familyId).getState())?.revoked).toBe(
      false,
    )
  })

  it("preserves one active administrator under concurrent group demotions", async () => {
    const second = await createUser(env, {
      email: "group.admin@pangda.app",
      name: "Group Admin",
    })
    await env.DB.prepare(
      "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, 'grp_seed_admins', unixepoch())",
    )
      .bind(second.id)
      .run()

    const results = await Promise.all([
      setUserGroupsPreservingActiveAdmin(env, adminUserId, []),
      setUserGroupsPreservingActiveAdmin(env, second.id, []),
    ])
    expect(results.sort()).toEqual([false, true])
    const remaining = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM user_groups WHERE group_id = 'grp_seed_admins'",
    ).first<{ count: number }>()
    expect(remaining?.count).toBe(1)
  })
})

describe("admin permission-group access", () => {
  it("round-trips sorted assignments and preserves them across rename", async () => {
    const created = await req("POST", "/admin/groups", {
      name: "test-access-roundtrip",
      description: "Access round trip",
    })
    const group = await created.json<{ id: string }>()
    expect(await (await req("GET", `/admin/groups/${group.id}/access`)).json()).toEqual({
      client_ids: [],
      resource_uris: [],
    })

    const updated = await req("PUT", `/admin/groups/${group.id}/access`, {
      client_ids: ["pangda_cli", "pangda_app", "pangda_cli"],
      resource_uris: ["https://app.pangda.app", "https://api.pangda.app"],
    })
    expect(updated.status).toBe(200)
    expect(await updated.json()).toEqual({
      client_ids: ["pangda_app", "pangda_cli"],
      resource_uris: ["https://api.pangda.app", "https://app.pangda.app"],
    })

    expect(
      (
        await req("PATCH", `/admin/groups/${group.id}`, {
          name: "test-access-renamed",
        })
      ).status,
    ).toBe(200)
    expect(await (await req("GET", `/admin/groups/${group.id}/access`)).json()).toEqual({
      client_ids: ["pangda_app", "pangda_cli"],
      resource_uris: ["https://api.pangda.app", "https://app.pangda.app"],
    })
  })

  it("rejects invalid and oversized targets without changing either set", async () => {
    const group = await (
      await req("POST", "/admin/groups", { name: "test-access-validation" })
    ).json<{ id: string }>()
    const path = `/admin/groups/${group.id}/access`
    const baseline = {
      client_ids: ["pangda_app"],
      resource_uris: ["https://api.pangda.app"],
    }
    expect((await req("PUT", path, baseline)).status).toBe(200)

    expect((await req("GET", "/admin/groups/missing/access")).status).toBe(404)
    expect((await req("PUT", "/admin/groups/missing/access", baseline)).status).toBe(404)
    for (const invalid of [
      { client_ids: ["missing"], resource_uris: baseline.resource_uris },
      { client_ids: ["svc_internal_worker"], resource_uris: baseline.resource_uris },
      { client_ids: baseline.client_ids, resource_uris: ["urn:test:missing"] },
    ]) {
      const response = await req("PUT", path, invalid)
      expect(response.status).toBe(400)
      expect(await response.json()).toEqual({ error: "invalid_access_target" })
      expect(await (await req("GET", path)).json()).toEqual(baseline)
    }

    const tooMany = Array.from({ length: 101 }, (_, index) => `missing-${index}`)
    expect((await req("PUT", path, { client_ids: tooMany, resource_uris: [] })).status).toBe(400)
    expect((await req("PUT", path, { client_ids: [], resource_uris: tooMany })).status).toBe(400)
    expect(await (await req("GET", path)).json()).toEqual(baseline)
  })

  it("fails closed after group, client, and resource deletion cascades", async () => {
    const group = await (await req("POST", "/admin/groups", { name: "test-access-cascade" })).json<{
      id: string
    }>()
    const clientId = "test_access_cascade"
    const resourceUri = "urn:test:access-cascade"
    const clientInsertSql = `INSERT INTO oauth_clients
       (client_id, client_secret_hash, type, client_kind, name, redirect_uris_json,
        allowed_scopes_json, allowed_grant_types_json, allowed_resources_json,
        default_resource, require_pkce, enabled, created_at, updated_at)
     VALUES (?, NULL, 'public', 'application', 'Cascade app', '[]', '["openid"]',
             '["authorization_code"]', ?, ?, 1, 1, unixepoch(), unixepoch())`
    const resourceInsertSql = `INSERT INTO oauth_resources
       (resource_uri, name, allowed_scopes_json, enabled, created_at, updated_at)
     VALUES (?, 'Cascade API', '["openid"]', 1, unixepoch(), unixepoch())`
    await env.DB.batch([
      env.DB.prepare(resourceInsertSql).bind(resourceUri),
      env.DB.prepare(clientInsertSql).bind(clientId, JSON.stringify([resourceUri]), resourceUri),
    ])
    await env.DB.prepare(
      "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, ?, unixepoch())",
    )
      .bind(regularUserId, group.id)
      .run()
    const path = `/admin/groups/${group.id}/access`
    const assignment = { client_ids: [clientId], resource_uris: [resourceUri] }
    expect((await req("PUT", path, assignment)).status).toBe(200)
    expect(
      await evaluateUserTokenAccess(env, {
        userId: regularUserId,
        clientId,
        resourceUri,
        scopes: ["openid"],
      }),
    ).toEqual({ allowed: true })

    expect((await req("DELETE", `/admin/clients/${clientId}`)).status).toBe(200)
    await env.DB.prepare(clientInsertSql)
      .bind(clientId, JSON.stringify([resourceUri]), resourceUri)
      .run()
    expect(
      await evaluateUserTokenAccess(env, {
        userId: regularUserId,
        clientId,
        resourceUri,
        scopes: ["openid"],
      }),
    ).toEqual({ allowed: false, reason: "application" })

    expect((await req("PUT", path, assignment)).status).toBe(200)
    await env.DB.prepare("DELETE FROM oauth_resources WHERE resource_uri = ?")
      .bind(resourceUri)
      .run()
    await env.DB.prepare(resourceInsertSql).bind(resourceUri).run()
    expect(
      await evaluateUserTokenAccess(env, {
        userId: regularUserId,
        clientId,
        resourceUri,
        scopes: ["openid"],
      }),
    ).toEqual({ allowed: false, reason: "resource" })

    expect((await req("PUT", path, assignment)).status).toBe(200)
    expect((await req("DELETE", `/admin/groups/${group.id}`)).status).toBe(200)
    expect(
      await evaluateUserTokenAccess(env, {
        userId: regularUserId,
        clientId,
        resourceUri,
        scopes: ["openid"],
      }),
    ).toEqual({ allowed: false, reason: "application" })
  })
})

describe("admin clients", () => {
  it("creates a confidential client whose secret works for client_credentials", async () => {
    const res = await req("POST", "/admin/clients", {
      client_id: "test_svc",
      name: "Test Service",
      type: "confidential",
      client_kind: "service",
      allowed_scopes: ["api.read"],
      allowed_grant_types: ["client_credentials"],
      allowed_resources: ["https://api.pangda.app"],
      default_resource: "https://api.pangda.app",
      require_pkce: true,
    })
    expect(res.status).toBe(201)
    const body = await res.json<{ client_secret: string; has_secret: boolean }>()
    expect(body.has_secret).toBe(true)

    const token = await SELF.fetch(`${ISSUER}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${btoa(`test_svc:${body.client_secret}`)}`,
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        scope: "api.read",
        resource: "https://api.pangda.app",
      }).toString(),
    })
    expect(token.status).toBe(200)
  })

  it("rotates a secret and toggles enabled", async () => {
    await req("POST", "/admin/clients", {
      client_id: "test_rot",
      name: "Rot",
      type: "confidential",
      client_kind: "service",
      allowed_scopes: ["api.read"],
      allowed_grant_types: ["client_credentials"],
      allowed_resources: ["https://api.pangda.app"],
      default_resource: "https://api.pangda.app",
      require_pkce: true,
    })
    expect(
      (
        await (
          await req("POST", "/admin/clients/test_rot/rotate-secret")
        ).json<{ client_secret: string }>()
      ).client_secret,
    ).toBeTruthy()
    expect((await req("POST", "/admin/clients/test_rot/disable")).status).toBe(200)
    expect((await req("POST", "/admin/clients/test_rot/enable")).status).toBe(200)
  })

  it("never exposes secret hashes in listings", async () => {
    const body = await (await req("GET", "/admin/clients")).json<{
      clients: Array<Record<string, unknown>>
    }>()
    for (const client of body.clients) {
      expect(client["client_secret_hash"]).toBeUndefined()
      expect(client["clientSecretHash"]).toBeUndefined()
    }
  })

  it("rejects attempts to disable mandatory S256 PKCE", async () => {
    const response = await req("POST", "/admin/clients", {
      client_id: "test_pkce_downgrade",
      name: "PKCE Downgrade",
      type: "public",
      client_kind: "application",
      require_pkce: false,
    })

    expect(response.status).toBe(400)
    expect((await response.json<{ error: string }>()).error).toBe("invalid_request")
  })

  it("rejects unsafe post-logout redirect registrations", async () => {
    const response = await req("POST", "/admin/clients", {
      client_id: "test_unsafe_logout",
      name: "Unsafe Logout",
      type: "public",
      client_kind: "application",
      post_logout_redirect_uris: ["javascript:alert(1)"],
    })

    expect(response.status).toBe(400)
    expect((await response.json<{ error: string }>()).error).toBe("invalid_request")
  })
})

describe("admin resources", () => {
  it("creates, lists, and patches a resource", async () => {
    expect(
      (
        await req("POST", "/admin/resources", {
          resource_uri: "urn:test:widget",
          name: "Widget",
          allowed_scopes: ["widget.read"],
        })
      ).status,
    ).toBe(201)
    const list = await (await req("GET", "/admin/resources")).json<{
      resources: Array<{ resource_uri: string }>
    }>()
    expect(list.resources.some((r) => r.resource_uri === "urn:test:widget")).toBe(true)

    const patched = await req("PATCH", "/admin/resources/urn:test:widget", {
      name: "Widget v2",
      enabled: false,
    })
    expect((await patched.json<{ name: string }>()).name).toBe("Widget v2")
  })

  it("deletes a resource and retires every stored authorization path", async () => {
    const resourceUri = "urn:test:delete-resource"
    const clientId = "test_resource_delete"
    expect(
      (
        await req("POST", "/admin/resources", {
          resource_uri: resourceUri,
          name: "Delete Resource",
          allowed_scopes: ["openid"],
        })
      ).status,
    ).toBe(201)
    await env.DB.prepare(
      `INSERT INTO oauth_clients
         (client_id, client_secret_hash, type, client_kind, name, redirect_uris_json,
          allowed_scopes_json, allowed_grant_types_json, allowed_resources_json,
          default_resource, require_pkce, enabled, created_at, updated_at)
       VALUES (?, NULL, 'public', 'application', 'Resource delete client', '[]',
               '["openid"]', '["authorization_code","refresh_token"]', ?, ?, 1, 1,
               unixepoch(), unixepoch())`,
    )
      .bind(clientId, JSON.stringify([resourceUri]), resourceUri)
      .run()
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO oauth_resource_permission_groups (resource_uri, group_id, created_at)
         VALUES (?, 'grp_seed_employees', unixepoch())`,
      ).bind(resourceUri),
      env.DB.prepare(
        `INSERT INTO consents (id, user_id, client_id, scope, resource, created_at, updated_at)
         VALUES ('con_test_resource_delete', ?, ?, 'openid', ?, unixepoch(), unixepoch())`,
      ).bind(regularUserId, clientId, resourceUri),
      env.DB.prepare(
        `INSERT INTO authorization_grants
           (id, user_id, client_id, session_id, scope, resource, grant_type, created_at)
         VALUES ('grt_test_resource_delete', ?, ?, ?, 'openid', ?, 'authorization_code', unixepoch())`,
      ).bind(regularUserId, clientId, regularSessionId, resourceUri),
      env.DB.prepare(
        `INSERT INTO device_authorization_sessions
           (id, device_code_hash, user_code_hash, client_id, resource_uri, scope, status,
            user_id, expires_at, approved_at, created_at)
         VALUES ('dev_test_resource_delete', 'device-delete-hash', 'user-delete-hash', ?, ?,
                 'openid', 'approved', ?, unixepoch() + 600, unixepoch(), unixepoch())`,
      ).bind(clientId, resourceUri, regularUserId),
    ])
    const refresh = await issueRefreshToken(env, {
      userId: regularUserId,
      clientId,
      sessionId: regularSessionId,
      resource: resourceUri,
      scope: "openid",
      authTime: Math.floor(Date.now() / 1000),
      rememberMe: false,
    })

    const deleted = await req("DELETE", `/admin/resources/${encodeURIComponent(resourceUri)}`)
    expect(deleted.status).toBe(200)
    expect(await deleted.json()).toEqual({ deleted: true })
    expect(
      (await req("DELETE", `/admin/resources/${encodeURIComponent(resourceUri)}`)).status,
    ).toBe(404)

    const client = await env.DB.prepare(
      "SELECT allowed_resources_json, default_resource FROM oauth_clients WHERE client_id = ?",
    )
      .bind(clientId)
      .first<{ allowed_resources_json: string; default_resource: string | null }>()
    expect(JSON.parse(client?.allowed_resources_json ?? "null")).toEqual([])
    expect(client?.default_resource).toBeNull()
    expect(
      (
        await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM oauth_resource_permission_groups WHERE resource_uri = ?",
        )
          .bind(resourceUri)
          .first<{ count: number }>()
      )?.count,
    ).toBe(0)
    expect(
      (
        await env.DB.prepare("SELECT COUNT(*) AS count FROM consents WHERE resource = ?")
          .bind(resourceUri)
          .first<{ count: number }>()
      )?.count,
    ).toBe(0)
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM refresh_tokens WHERE id = ?")
          .bind(refresh.familyId)
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).not.toBeNull()
    expect(
      (
        await env.DB.prepare(
          "SELECT revoked_at FROM authorization_grants WHERE id = 'grt_test_resource_delete'",
        ).first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).not.toBeNull()
    expect(
      await env.DB.prepare(
        "SELECT status, denied_at FROM device_authorization_sessions WHERE id = 'dev_test_resource_delete'",
      ).first(),
    ).toMatchObject({ status: "denied", denied_at: expect.any(Number) })
  })
})

describe("admin audit + device sessions", () => {
  it("lists audit logs", async () => {
    const res = await req("GET", "/admin/audit-logs")
    expect(res.status).toBe(200)
    expect(Array.isArray((await res.json<{ logs: unknown[] }>()).logs)).toBe(true)
  })

  it("lists and revokes device sessions", async () => {
    await SELF.fetch(`${ISSUER}/oauth/device_authorization`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "pangda_cli",
        scope: "openid",
        resource: "https://api.pangda.app",
      }).toString(),
    })
    const sessions = (
      await (
        await req("GET", "/admin/device-sessions")
      ).json<{ device_sessions: Array<{ id: string }> }>()
    ).device_sessions
    expect(sessions.length).toBeGreaterThanOrEqual(1)
    const id = sessions[0]?.id ?? ""
    expect((await req("POST", `/admin/device-sessions/${id}/revoke`)).status).toBe(200)
  })
})
