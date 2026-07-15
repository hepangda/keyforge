import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { setUserPassword, verifyUserPassword } from "../../src/auth/password"
import { createSession, getSessionByToken } from "../../src/auth/session"
import { createClient, getClientById } from "../../src/db/queries/clients"
import { getResourceByUri } from "../../src/db/queries/resources"
import {
  createUser,
  getGroupByName,
  getUserByEmail,
  getUserById,
  getUserGroupNames,
} from "../../src/db/queries/users"
import { hashClientSecret } from "../../src/security/client-secret"

const ISSUER = "https://auth.pangda.app"

beforeEach(async () => {
  await env.DB.batch([env.DB.prepare("DELETE FROM sessions")])
  await env.RATE_LIMIT.getByName("login:unknown:admin").reset()
})

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

async function loginAs(email: string, password: string): Promise<string> {
  const page = await SELF.fetch(`${ISSUER}/login`)
  const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf")
  const res = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ email, password, csrf_token: csrf }).toString(),
    redirect: "manual",
  })
  return cookieValue(res.headers.getSetCookie(), "__Host-keyforge_session")
}

async function consoleCsrf(session: string): Promise<string> {
  const res = await SELF.fetch(`${ISSUER}/console/clients/new`, {
    headers: { cookie: `__Host-keyforge_session=${session}` },
  })
  return cookieValue(res.headers.getSetCookie(), "__Host-keyforge_csrf")
}

function postForm(
  path: string,
  session: string,
  csrf: string,
  fields: Record<string, string>,
): Promise<Response> {
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_session=${session}; __Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ csrf_token: csrf, ...fields }).toString(),
    redirect: "manual",
  })
}

describe("console access control", () => {
  it("redirects anonymous visitors to sign in", async () => {
    const res = await SELF.fetch(`${ISSUER}/console`, { redirect: "manual" })
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("/login")
  })

  it("forbids non-admin users with 403", async () => {
    const user = await createUser(env, { email: "nobody@pangda.app" })
    await setUserPassword(env, user.id, "hunter2 hunter2")
    const session = await loginAs("nobody@pangda.app", "hunter2 hunter2")
    const res = await SELF.fetch(`${ISSUER}/console`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(res.status).toBe(403)
  })

  it("renders the console overview for an admin", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const res = await SELF.fetch(`${ISSUER}/console`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(res.status).toBe(200)
    const page = await res.text()
    expect(page).toContain("Admin console")
    expect(page).toContain('class="shell"')
    expect(page).toContain('class="shell-tabs"')
    expect(page).toContain(".shell{width:min(100%,1080px)")
    expect(page).toContain("html{scrollbar-gutter:stable}")
    expect(page).toContain("<h1>Overview</h1>")
    expect(page).toContain("Get KeyForge ready")
  })

  it("requires recent authentication before entering a management form", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const record = await getSessionByToken(env, session)
    expect(record).not.toBeNull()
    await env.DB.prepare("UPDATE sessions SET auth_time = 0 WHERE id = ?")
      .bind(record?.id ?? "")
      .run()

    const overview = await SELF.fetch(`${ISSUER}/console`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(overview.status).toBe(200)

    const form = await SELF.fetch(`${ISSUER}/console/users/new`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(form.status).toBe(302)
    const login = new URL(form.headers.get("location") ?? "", ISSUER)
    expect(login.pathname).toBe("/login")
    expect(login.searchParams.get("reauth")).toBe("1")
    expect(login.searchParams.get("return_to")).toBe("/console/users/new")

    const destructiveForm = await SELF.fetch(`${ISSUER}/console/clients/demo_local/delete`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(destructiveForm.status).toBe(302)
    const destructiveLogin = new URL(destructiveForm.headers.get("location") ?? "", ISSUER)
    expect(destructiveLogin.searchParams.get("return_to")).toBe(
      "/console/clients/demo_local/delete",
    )

    const staleMutation = await SELF.fetch(`${ISSUER}/console/resources`, {
      method: "POST",
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(staleMutation.status).toBe(302)
    const mutationLogin = new URL(staleMutation.headers.get("location") ?? "", ISSUER)
    expect(mutationLogin.searchParams.get("return_to")).toBe("/console/resources/new")
  })
})

describe("console users", () => {
  it("creates a group and a password user with that membership", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const groupResponse = await postForm("/console/groups", session, csrf, {
      name: "console-operators",
      description: "Console-created operators",
    })
    expect(groupResponse.status).toBe(302)
    const group = await getGroupByName(env, "console-operators")
    expect(group).not.toBeNull()

    const createResponse = await postForm("/console/users", session, csrf, {
      email: "console.user@pangda.app",
      alias: "consoleuser",
      name: "Console User",
      email_verified: "1",
      password: "console password 123",
      group_ids: group?.id ?? "",
    })
    expect(createResponse.status).toBe(302)
    expect(createResponse.headers.get("location")).toContain("flash=user_created")
    const user = await getUserByEmail(env, "console.user@pangda.app")
    expect(user?.emailVerified).toBe(true)
    expect(await verifyUserPassword(env, user?.id ?? "", "console password 123")).toBe(true)
    expect(await getUserGroupNames(env, user?.id ?? "")).toEqual(["console-operators"])
  })

  it("requires the exact current group name before deletion", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const created = await postForm("/console/groups", session, csrf, {
      name: "temporary-reviewers",
      description: "Safe to remove",
    })
    expect(created.status).toBe(302)
    const group = await getGroupByName(env, "temporary-reviewers")
    expect(group).not.toBeNull()

    const confirmation = await SELF.fetch(
      `${ISSUER}/console/groups/${group?.id ?? "missing"}/delete`,
      { headers: { cookie: `__Host-keyforge_session=${session}` } },
    )
    expect(confirmation.status).toBe(200)
    const confirmationPage = await confirmation.text()
    expect(confirmationPage).toContain("Delete permission group?")
    expect(confirmationPage).toContain("Type temporary-reviewers to confirm")

    const mismatch = await postForm(
      `/console/groups/${group?.id ?? "missing"}/delete`,
      session,
      csrf,
      { confirmation: "Temporary-Reviewers" },
    )
    expect(mismatch.status).toBe(400)
    const mismatchPage = await mismatch.text()
    expect(mismatchPage).toContain("The group name did not match. Nothing was deleted.")
    expect(mismatchPage).toContain('name="confirmation"')
    expect(await getGroupByName(env, "temporary-reviewers")).not.toBeNull()

    const deleted = await postForm(
      `/console/groups/${group?.id ?? "missing"}/delete`,
      session,
      csrf,
      { confirmation: "temporary-reviewers" },
    )
    expect(deleted.status).toBe(302)
    expect(deleted.headers.get("location")).toContain("flash=group_deleted")
    expect(await getGroupByName(env, "temporary-reviewers")).toBeNull()
  })

  it("keeps the admins group protected from direct confirmation requests", async () => {
    const admins = await getGroupByName(env, "admins")
    expect(admins).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const path = `/console/groups/${admins?.id ?? "missing"}/delete`

    const confirmation = await SELF.fetch(`${ISSUER}${path}`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(confirmation.status).toBe(302)
    expect(confirmation.headers.get("location")).toContain("flash=protected_group")

    const deletion = await postForm(path, session, csrf, { confirmation: "admins" })
    expect(deletion.status).toBe(302)
    expect(deletion.headers.get("location")).toContain("flash=protected_group")
    expect(await getGroupByName(env, "admins")).not.toBeNull()
  })

  it("renders the invitation form without exposing credential material", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const res = await SELF.fetch(`${ISSUER}/console/users/new`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(res.status).toBe(200)
    const page = await res.text()
    expect(page).toContain("Leaving the password blank sends a secure one-hour invitation link")
    expect(page).not.toContain("/password/reset?token=")
  })

  it("re-renders invalid user creation values but always clears the password", async () => {
    const group = await getGroupByName(env, "employees")
    expect(group).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const password = "Tiny"

    const res = await postForm("/console/users", session, csrf, {
      email: "Draft.User@Example.COM",
      alias: "DraftUser",
      name: "Draft & User",
      email_verified: "1",
      group_ids: group?.id ?? "",
      password,
    })
    expect(res.status).toBe(400)
    const page = await res.text()
    expect(page).toContain("Initial passwords must contain 6–128 characters")
    expect(page).toContain("the initial password was cleared")
    expect(page).toContain('value="Draft.User@Example.COM"')
    expect(page).toContain('value="DraftUser"')
    expect(page).toContain('value="Draft &amp; User"')
    expect(page).toContain('name="email_verified" value="1" checked')
    expect(page).toContain(`name="group_ids" value="${group?.id ?? ""}" checked`)
    expect(page).toContain('type="password" name="password" value=""')
    expect(page).not.toContain(password)
    expect(await getUserByEmail(env, "draft.user@example.com")).toBeNull()
  })

  it("disables a user through the edit form", async () => {
    const target = await createUser(env, { email: "target@pangda.app" })
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm(`/console/users/${target.id}`, session, csrf, {
      alias: target.alias,
      disabled: "1",
    })
    expect(res.status).toBe(302)
    expect((await getUserById(env, target.id))?.disabled).toBe(true)
  })

  it("revokes a user's sessions", async () => {
    const target = await createUser(env, { email: "target2@pangda.app" })
    const { token } = await createSession(env, {
      userId: target.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    expect(await getSessionByToken(env, token)).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm(`/console/users/${target.id}/revoke-sessions`, session, csrf, {})
    expect(res.status).toBe(302)
    expect(await getSessionByToken(env, token)).toBeNull()
  })

  it("keeps the last active administrator enabled and in the admins group", async () => {
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)

    const disable = await postForm(`/console/users/${admin?.id}`, session, csrf, {
      alias: admin?.alias ?? "admin",
      disabled: "1",
    })
    expect(disable.headers.get("location")).toContain("flash=last_admin")
    expect((await getUserById(env, admin?.id ?? ""))?.disabled).toBe(false)

    const demote = await postForm(`/console/users/${admin?.id}/groups`, session, csrf, {})
    expect(demote.headers.get("location")).toContain("flash=last_admin")
    expect(await getUserGroupNames(env, admin?.id ?? "")).toContain("admins")
  })
})

describe("console clients", () => {
  it("renders a guided wizard with registered API choices and safe defaults", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const res = await SELF.fetch(`${ISSUER}/console/clients/new`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(res.status).toBe(200)
    const page = await res.text()
    expect(page).toContain("data-console-wizard")
    expect(page).toContain('src="/assets/console.js"')
    expect(page).toContain("Machine to machine")
    expect(page).toContain('name="redirect_uris" rows="3" required')
    expect(page).toContain('name="allowed_resources"')
    expect(page).toContain("data-resource-scopes=")
    expect(page).toMatch(/name="allowed_resources"[^>]+ checked/)
    expect(page).toMatch(/name="default_resource" value="[^"]+"/)
  })

  it("creates a confidential client and reveals the secret once", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm("/console/clients", session, csrf, {
      client_id: "cx_new",
      name: "Console Test",
      type: "confidential",
      client_kind: "application",
      redirect_uris: "https://cx.example/callback",
      allowed_scopes: "openid\napi.read",
      allowed_grant_types: "authorization_code",
      allowed_resources: "https://api.pangda.app",
      default_resource: "https://api.pangda.app",
      require_pkce: "1",
    })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain("Client secret")
    const created = await getClientById(env, "cx_new")
    expect(created).not.toBeNull()
    expect(created?.clientSecretHash).not.toBeNull()
  })

  it("accepts the machine-to-machine policy generated by the wizard", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm("/console/clients", session, csrf, {
      client_id: "cx_wizard_service",
      name: "Wizard service",
      type: "confidential",
      client_kind: "service",
      redirect_uris: "",
      post_logout_redirect_uris: "",
      allowed_scopes: "api.read",
      allowed_grant_types: "client_credentials",
      allowed_resources: "https://api.pangda.app",
      default_resource: "https://api.pangda.app",
    })
    expect(res.status).toBe(200)
    const created = await getClientById(env, "cx_wizard_service")
    expect(created).toMatchObject({
      clientKind: "service",
      type: "confidential",
      redirectUris: [],
      allowedScopes: ["api.read"],
      allowedGrantTypes: ["client_credentials"],
      allowedResources: ["https://api.pangda.app"],
    })
  })

  it("re-renders every non-secret new-client field with a specific redirect error", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm("/console/clients", session, csrf, {
      client_id: "cx_draft_new",
      name: "Draft & Client",
      type: "confidential",
      client_kind: "application",
      redirect_uris: "javascript:alert(1)\nhttps://draft.example/callback",
      post_logout_redirect_uris: "https://draft.example/logout",
      allowed_scopes: "openid\napi.read",
      allowed_grant_types: "authorization_code",
      allowed_resources: "https://api.pangda.app",
      default_resource: "https://api.pangda.app",
    })

    expect(res.status).toBe(400)
    const page = await res.text()
    expect(page).toContain(
      "Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain native scheme",
    )
    expect(page).toContain('name="client_id" value="cx_draft_new"')
    expect(page).toContain('name="name" value="Draft &amp; Client"')
    expect(page).toContain('name="type" value="confidential" checked')
    expect(page).toContain('name="client_kind" value="application" checked')
    expect(page).toContain("javascript:alert(1)\nhttps://draft.example/callback")
    expect(page).toContain("https://draft.example/logout")
    expect(page).toContain("openid\napi.read")
    expect(page).toContain("authorization_code")
    expect(page).toContain('name="default_resource" value="https://api.pangda.app"')
    expect(await getClientById(env, "cx_draft_new")).toBeNull()
  })

  it("re-renders edited client fields with the configuration policy error", async () => {
    await createClient(
      env,
      {
        clientId: "cx_draft_edit",
        name: "Original client",
        type: "public",
        clientKind: "application",
        redirectUris: ["https://original.example/callback"],
        postLogoutRedirectUris: [],
        allowedScopes: ["openid", "api.read"],
        allowedGrantTypes: ["authorization_code"],
        allowedResources: ["https://api.pangda.app"],
        defaultResource: "https://api.pangda.app",
        requirePkce: true,
      },
      null,
    )
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm("/console/clients/cx_draft_edit", session, csrf, {
      name: "Updated & Retained",
      redirect_uris: "https://updated.example/callback",
      post_logout_redirect_uris: "https://updated.example/logout",
      allowed_scopes: "openid\napi.read",
      allowed_grant_types: "authorization_code",
      allowed_resources: "https://api.pangda.app",
      default_resource: "https://not-selected.example",
    })

    expect(res.status).toBe(400)
    const page = await res.text()
    expect(page).toContain(
      "Configuration error: default_resource must be one of allowed_resources.",
    )
    expect(page).toContain('name="name" value="Updated &amp; Retained"')
    expect(page).toContain("https://updated.example/callback")
    expect(page).toContain("https://updated.example/logout")
    expect(page).toContain("openid\napi.read")
    expect(page).toContain('value="https://not-selected.example"')
    expect(await getClientById(env, "cx_draft_edit")).toMatchObject({
      name: "Original client",
      defaultResource: "https://api.pangda.app",
    })
  })

  it("disables and deletes a client", async () => {
    await createClient(
      env,
      {
        clientId: "cx_manage",
        name: "Manage Me",
        type: "public",
        clientKind: "application",
        redirectUris: [],
        allowedScopes: [],
        allowedGrantTypes: [],
        allowedResources: [],
        defaultResource: null,
        requirePkce: true,
      },
      null,
    )
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)

    await postForm("/console/clients/cx_manage/disable", session, csrf, {})
    expect((await getClientById(env, "cx_manage"))?.enabled).toBe(false)

    const confirmation = await SELF.fetch(`${ISSUER}/console/clients/cx_manage/delete`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(confirmation.status).toBe(200)
    expect(await confirmation.text()).toContain("Delete OAuth client?")

    const mismatch = await postForm("/console/clients/cx_manage/delete", session, csrf, {
      confirmation: "wrong-client",
    })
    expect(mismatch.status).toBe(400)
    expect(await getClientById(env, "cx_manage")).not.toBeNull()

    const del = await postForm("/console/clients/cx_manage/delete", session, csrf, {
      confirmation: "cx_manage",
    })
    expect(del.status).toBe(302)
    expect(await getClientById(env, "cx_manage")).toBeNull()
  })

  it("requires a typed confirmation before rotating a confidential client secret", async () => {
    await createClient(
      env,
      {
        clientId: "cx_rotate",
        name: "Rotate Me",
        type: "confidential",
        clientKind: "service",
        redirectUris: [],
        allowedScopes: ["api.read"],
        allowedGrantTypes: ["client_credentials"],
        allowedResources: ["https://api.pangda.app"],
        defaultResource: "https://api.pangda.app",
        requirePkce: true,
      },
      await hashClientSecret("old-secret"),
    )
    const before = (await getClientById(env, "cx_rotate"))?.clientSecretHash
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)

    const page = await SELF.fetch(`${ISSUER}/console/clients/cx_rotate/rotate-secret`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(page.status).toBe(200)
    expect(await page.text()).toContain("Rotate client secret?")

    const mismatch = await postForm("/console/clients/cx_rotate/rotate-secret", session, csrf, {
      confirmation: "wrong-client",
    })
    expect(mismatch.status).toBe(400)
    expect((await getClientById(env, "cx_rotate"))?.clientSecretHash).toBe(before)

    const rotated = await postForm("/console/clients/cx_rotate/rotate-secret", session, csrf, {
      confirmation: "cx_rotate",
    })
    expect(rotated.status).toBe(200)
    expect(await rotated.text()).toContain("Client secret")
    expect((await getClientById(env, "cx_rotate"))?.clientSecretHash).not.toBe(before)
  })

  it("ignores a mutation with an invalid CSRF token", async () => {
    await createClient(
      env,
      {
        clientId: "cx_csrf",
        name: "Keep Enabled",
        type: "public",
        clientKind: "application",
        redirectUris: [],
        allowedScopes: [],
        allowedGrantTypes: [],
        allowedResources: [],
        defaultResource: null,
        requirePkce: true,
      },
      null,
    )
    const session = await loginAs("admin", "test-admin-password-2026")
    const res = await SELF.fetch(`${ISSUER}/console/clients/cx_csrf/disable`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `__Host-keyforge_session=${session}`,
      },
      body: new URLSearchParams({ csrf_token: "bogus" }).toString(),
      redirect: "manual",
    })
    expect(res.status).toBe(302)
    expect((await getClientById(env, "cx_csrf"))?.enabled).toBe(true)
  })
})

describe("console resources", () => {
  it("creates a resource through the form", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const res = await postForm("/console/resources", session, csrf, {
      resource_uri: "https://api.console.test",
      name: "Console API",
      allowed_scopes: "api.read\napi.write",
    })
    expect(res.status).toBe(302)
    const created = await getResourceByUri(env, "https://api.console.test")
    expect(created?.name).toBe("Console API")
    expect(created?.allowedScopes).toEqual(["api.read", "api.write"])
  })
})

describe("console read pages", () => {
  it("renders users, clients, resources, devices and audit for an admin", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const cookie = `__Host-keyforge_session=${session}`
    for (const path of [
      "/console/users",
      "/console/clients",
      "/console/resources",
      "/console/devices",
      "/console/audit",
    ]) {
      const res = await SELF.fetch(`${ISSUER}${path}`, { headers: { cookie } })
      expect(res.status).toBe(200)
    }
  })

  it("does not link to an empty tail page and keeps a manual empty tail recoverable", async () => {
    const countRow = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first<{
      total: number
    }>()
    const total = countRow?.total ?? 1
    const session = await loginAs("admin", "test-admin-password-2026")
    const cookie = `__Host-keyforge_session=${session}`

    const exactPage = await SELF.fetch(`${ISSUER}/console/users?limit=${total}`, {
      headers: { cookie },
    })
    const exactHtml = await exactPage.text()
    expect(exactHtml).not.toContain(">Next</a>")

    const emptyTail = await SELF.fetch(`${ISSUER}/console/users?limit=${total}&offset=${total}`, {
      headers: { cookie },
    })
    const emptyHtml = await emptyTail.text()
    expect(emptyHtml).toContain("No results on this page.")
    expect(emptyHtml).toContain(">Previous</a>")
    expect(emptyHtml).not.toContain(`Showing ${total + 1}–${total}`)
  })
})
