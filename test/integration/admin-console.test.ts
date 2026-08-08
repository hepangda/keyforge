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
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare(
      "DELETE FROM oauth_client_permission_groups WHERE group_id = 'grp_seed_employees'",
    ),
    env.DB.prepare(
      "DELETE FROM oauth_resource_permission_groups WHERE group_id = 'grp_seed_employees'",
    ),
    env.DB.prepare(
      `INSERT INTO oauth_client_permission_groups (client_id, group_id, created_at)
       SELECT client_id, 'grp_seed_employees', unixepoch()
       FROM oauth_clients
       WHERE client_id IN ('pangda_app', 'cloudflare_one', 'pangda_cli', 'hermes_dashboard')`,
    ),
    env.DB.prepare(
      `INSERT INTO oauth_resource_permission_groups (resource_uri, group_id, created_at)
       SELECT resource_uri, 'grp_seed_employees', unixepoch()
       FROM oauth_resources
       WHERE resource_uri IN ('https://api.pangda.app', 'https://app.pangda.app',
                              'urn:pangda:cloudflare-one', 'urn:pangda:hermes-agent')`,
    ),
  ])
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
  fields: Record<string, string | readonly string[]>,
): Promise<Response> {
  const body = new URLSearchParams({ csrf_token: csrf })
  for (const [name, value] of Object.entries(fields)) {
    if (typeof value === "string") {
      body.set(name, value)
    } else {
      for (const item of value) body.append(name, item)
    }
  }
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_session=${session}; __Host-keyforge_csrf=${csrf}`,
    },
    body: body.toString(),
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
    const page = await res.text()
    expect(page).toContain('class="shell"')
    expect(page).toContain("--layout-card-max:480px")
    expect(page).toContain("--layout-shell-max:1080px")
    expect(page).toContain("nobody@pangda.app")
    expect(page).toContain('href="/">Your account</a>')
    expect(page).toContain('href="/logout">Sign out</a>')
    expect(page).not.toContain('class="shell-tabs"')
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
    expect(page).toContain(".shell{width:min(100%,var(--layout-shell-max))")
    expect(page).toContain(".secret{margin:.4rem 0 0;padding:.85rem 1rem")
    expect(page).toContain("font:500 .9rem var(--font-mono);overflow-wrap:anywhere")
    expect(page).not.toContain(".form-grid{display:grid;gap:1.1rem;max-width")
    expect(page).not.toContain(".form-grid--method{max-width")
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
    expect(mutationLogin.searchParams.get("return_to")).toBe("/console/resources/new?draft=1")
  })
})

describe("console users", () => {
  it("separates Groups from the user directory and preserves invalid form values", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const cookie = `__Host-keyforge_session=${session}`
    const users = await SELF.fetch(`${ISSUER}/console/users`, { headers: { cookie } })
    const usersHtml = await users.text()
    expect(usersHtml).toContain('href="/console/groups"')
    expect(usersHtml).toContain("Permission groups")

    const groups = await SELF.fetch(`${ISSUER}/console/groups`, { headers: { cookie } })
    const groupsHtml = await groups.text()
    expect(groupsHtml).toContain("Permission groups")
    expect(groupsHtml).toContain("Protected")
    expect(groupsHtml).toContain('href="/console/groups/new"')
    expect(groupsHtml).not.toContain("Manage membership and the claims applications receive.")
    expect(groupsHtml).not.toContain("Use groups to grant application and administrator claims.")
    expect(groupsHtml).not.toContain("Group membership is included in identity claims")

    const form = await SELF.fetch(`${ISSUER}/console/groups/new`, { headers: { cookie } })
    expect(form.status).toBe(200)
    const csrf = cookieValue(form.headers.getSetCookie(), "__Host-keyforge_csrf")
    const invalid = await postForm("/console/groups", session, csrf, {
      name: "Bad Group Name",
      description: "Keep this description",
    })
    expect(invalid.status).toBe(400)
    const invalidHtml = await invalid.text()
    expect(invalidHtml).toContain('value="Bad Group Name"')
    expect(invalidHtml).toContain('value="Keep this description"')

    const duplicate = await postForm("/console/groups", session, csrf, {
      name: "admins",
      description: "Protected duplicate",
    })
    expect(duplicate.status).toBe(400)
    expect(await duplicate.text()).toContain("already exists")
  })

  it("renders, saves, and validates application and API assignments", async () => {
    const employees = await getGroupByName(env, "employees")
    expect(employees).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const cookie = `__Host-keyforge_session=${session}`
    const path = `/console/groups/${employees?.id ?? "missing"}`
    const page = await SELF.fetch(`${ISSUER}${path}?view=access`, { headers: { cookie } })
    expect(page.status).toBe(200)
    const html = await page.text()
    for (const value of [
      "pangda_app",
      "cloudflare_one",
      "pangda_cli",
      "hermes_dashboard",
      "https://api.pangda.app",
      "https://app.pangda.app",
      "urn:pangda:cloudflare-one",
      "urn:pangda:hermes-agent",
    ]) {
      expect(html).toContain(`value="${value}" checked`)
    }
    expect(html).not.toContain('value="svc_internal_worker"')
    const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf")

    const saved = await postForm(`${path}/access`, session, csrf, {
      client_ids: ["pangda_app"],
      resource_uris: ["https://api.pangda.app"],
    })
    expect(saved.status).toBe(302)
    expect(saved.headers.get("location")).toContain("flash=group_access_updated")
    const reloaded = await SELF.fetch(`${ISSUER}${path}?view=access&flash=group_access_updated`, {
      headers: { cookie },
    })
    const reloadedHtml = await reloaded.text()
    expect(reloadedHtml).toContain("Permission-group access updated.")
    expect(reloadedHtml).toContain('value="pangda_app" checked')
    expect(reloadedHtml).toContain('value="https://api.pangda.app" checked')
    expect(reloadedHtml).not.toContain('value="pangda_cli" checked')

    const invalid = await postForm(`${path}/access`, session, csrf, {
      client_ids: ["pangda_app", "missing-client"],
      resource_uris: ["https://api.pangda.app", "urn:missing"],
    })
    expect(invalid.status).toBe(400)
    const invalidHtml = await invalid.text()
    expect(invalidHtml).toContain("Choose only existing user applications and APIs.")
    expect(invalidHtml).toContain('value="pangda_app" checked')
    expect(invalidHtml).toContain('value="https://api.pangda.app" checked')
    expect(invalidHtml).not.toContain("missing-client")
    expect(invalidHtml).not.toContain("urn:missing")
  })

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
      setup_mode: "password",
      password: "console password 123",
      password_confirm: "console password 123",
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

  it("allows admins access management while keeping settings and deletion protected", async () => {
    const admins = await getGroupByName(env, "admins")
    expect(admins).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const detailPath = `/console/groups/${admins?.id ?? "missing"}`
    const access = await SELF.fetch(`${ISSUER}${detailPath}`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(access.status).toBe(200)
    const accessHtml = await access.text()
    expect(accessHtml).toContain(`action="${detailPath}/access"`)
    expect(accessHtml).toContain('value="pangda_admin" checked')
    expect(accessHtml).not.toContain(`href="${detailPath}/delete"`)
    expect(accessHtml).not.toContain('name="name"')

    const saved = await postForm(`${detailPath}/access`, session, csrf, {
      client_ids: ["pangda_admin"],
      resource_uris: ["https://admin.pangda.app"],
    })
    expect(saved.status).toBe(302)
    expect(saved.headers.get("location")).toContain("flash=group_access_updated")

    const settings = await SELF.fetch(`${ISSUER}${detailPath}?view=settings`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
      redirect: "manual",
    })
    expect(settings.status).toBe(302)
    expect(settings.headers.get("location")).toContain("view=access")
    expect(settings.headers.get("location")).toContain("flash=protected_group")
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
    expect(page).toContain('name="setup_mode" value="invite" checked')
    expect(page).toContain("Send invitation")
    expect(page).toContain("Set initial password")
    expect(page).not.toContain("/password/reset?token=")
    expect(page).toContain(
      ".form-grid{display:grid;width:100%;grid-template-columns:repeat(2,minmax(0,1fr))",
    )
    expect(page).toContain('data-draft-key="keyforge:form:user:new"')

    const csrf = cookieValue(res.headers.getSetCookie(), "__Host-keyforge_csrf")
    const invited = await postForm("/console/users", session, csrf, {
      email: "invited.mode@example.test",
      alias: "invitedmode",
      setup_mode: "invite",
      password: "ignored password value",
      password_confirm: "does not match",
    })
    expect(invited.status).toBe(302)
    expect(invited.headers.get("location")).toContain("view=login-methods")
    expect(invited.headers.get("location")).toContain("flash=user_invited")
    const invitedUser = await getUserByEmail(env, "invited.mode@example.test")
    expect(invitedUser).not.toBeNull()
    expect(await verifyUserPassword(env, invitedUser?.id ?? "", "ignored password value")).toBe(
      false,
    )

    const unknown = await postForm("/console/users", session, csrf, {
      email: "unknown.mode@example.test",
      alias: "unknownmode",
      setup_mode: "legacy",
    })
    expect(unknown.status).toBe(400)
    expect(await unknown.text()).toContain("Choose how this user should set up their account")
    expect(await getUserByEmail(env, "unknown.mode@example.test")).toBeNull()
    expect(page).toContain(".form-grid--single{grid-template-columns:minmax(0,1fr)}")
    expect(page).toContain('class="field-cluster field--wide"')
    expect(page).toContain('class="form-actions"')
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
      setup_mode: "password",
      password_confirm: password,
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

  it("searches users literally and preserves the query through pagination", async () => {
    const literal = await createUser(env, {
      email: "literal.search@example.test",
      alias: "literal_name",
    })
    await createUser(env, { email: "wildcard@example.test", alias: "literalxname" })
    const session = await loginAs("admin", "test-admin-password-2026")
    const cookie = `__Host-keyforge_session=${session}`

    const underscore = await SELF.fetch(`${ISSUER}/console/users?q=_&limit=50`, {
      headers: { cookie },
    })
    const underscoreHtml = await underscore.text()
    expect(underscoreHtml).toContain("literal_name")
    expect(underscoreHtml).not.toContain("literalxname")
    expect(underscoreHtml).toContain('name="q" value="_"')
    expect(underscoreHtml).toContain("Search users")
    expect(underscoreHtml).toContain('href="/console/users">Clear</a>')

    const exactId = await SELF.fetch(
      `${ISSUER}/console/users?q=${encodeURIComponent(literal.id)}`,
      { headers: { cookie } },
    )
    expect(await exactId.text()).toContain("literal_name")

    const paged = await SELF.fetch(`${ISSUER}/console/users?q=literal&limit=1`, {
      headers: { cookie },
    })
    expect(await paged.text()).toContain("/console/users?q=literal&amp;limit=1&amp;offset=1")

    const percent = await SELF.fetch(`${ISSUER}/console/users?q=%25`, {
      headers: { cookie },
    })
    expect(await percent.text()).toContain("No users match this search.")
  })

  it("splits user details into tabs and reviews disable before mutation", async () => {
    const target = await createUser(env, { email: "target@pangda.app" })
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const detail = await SELF.fetch(`${ISSUER}/console/users/${target.id}?view=unknown`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    const detailHtml = await detail.text()
    expect(detailHtml).toContain('aria-label="User sections"')
    expect(detailHtml).toContain(target.id)
    expect(detailHtml).toContain('name="alias"')
    expect(detailHtml).not.toContain("Add password")
    expect(detailHtml).toContain(`/console/users/${target.id}?view=login-methods`)

    const saved = await postForm(`/console/users/${target.id}`, session, csrf, {
      alias: "renamedtarget",
      name: "Renamed Target",
    })
    expect(saved.status).toBe(302)
    expect(saved.headers.get("location")).toContain("view=profile")
    expect((await getUserById(env, target.id))?.disabled).toBe(false)
    expect((await getUserById(env, target.id))?.alias).toBe("renamedtarget")

    const review = await SELF.fetch(`${ISSUER}/console/users/${target.id}/disable`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(review.status).toBe(200)
    const reviewHtml = await review.text()
    expect(reviewHtml).toContain("immediately revokes every session and refresh token")
    const reviewCsrf = cookieValue(review.headers.getSetCookie(), "__Host-keyforge_csrf")
    const disabled = await postForm(`/console/users/${target.id}/disable`, session, reviewCsrf, {})
    expect(disabled.status).toBe(302)
    expect((await getUserById(env, target.id))?.disabled).toBe(true)
  })

  it("keeps typed user-detail values while clearing password secrets", async () => {
    const target = await createUser(env, { email: "feedback@pangda.app", alias: "feedback" })
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const profile = await postForm(`/console/users/${target.id}`, session, csrf, {
      alias: "bad alias",
      name: "Draft Name",
    })
    expect(profile.status).toBe(400)
    const profileHtml = await profile.text()
    expect(profileHtml).toContain('value="bad alias"')
    expect(profileHtml).toContain('value="Draft Name"')
    expect(profileHtml).toContain('aria-current="page">Profile</a>')

    const password = await postForm(`/console/users/${target.id}/passwords`, session, csrf, {
      name: "Temporary credential",
      password: "first password value",
      password_confirm: "different password value",
    })
    expect(password.status).toBe(400)
    const passwordHtml = await password.text()
    expect(passwordHtml).toContain('value="Temporary credential"')
    expect(passwordHtml).toContain('type="password" name="password" value=""')
    expect(passwordHtml).not.toContain("first password value")
    expect(passwordHtml).not.toContain("different password value")
    expect(passwordHtml).toContain('aria-current="page">Login methods</a>')
  })

  it("reviews and revokes a user's sessions", async () => {
    const target = await createUser(env, { email: "target2@pangda.app" })
    const { token } = await createSession(env, {
      userId: target.id,
      authMethod: "password",
      ttlSeconds: 3600,
    })
    const session = await loginAs("admin", "test-admin-password-2026")
    const tab = await SELF.fetch(`${ISSUER}/console/users/${target.id}?view=sessions`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    const tabHtml = await tab.text()
    expect(tabHtml).toContain("Last active")
    expect(tabHtml).toContain(`/console/users/${target.id}/revoke-sessions`)
    const review = await SELF.fetch(`${ISSUER}/console/users/${target.id}/revoke-sessions`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(review.status).toBe(200)
    const csrf = cookieValue(review.headers.getSetCookie(), "__Host-keyforge_csrf")
    const res = await postForm(`/console/users/${target.id}/revoke-sessions`, session, csrf, {})
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toContain("view=sessions")
    expect(await getSessionByToken(env, token)).toBeNull()
  })

  it("keeps the last active administrator enabled and in the admins group", async () => {
    const admin = await getUserByEmail(env, "admin")
    expect(admin).not.toBeNull()
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)

    const review = await SELF.fetch(`${ISSUER}/console/users/${admin?.id}/disable`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    const disableCsrf = cookieValue(review.headers.getSetCookie(), "__Host-keyforge_csrf")
    const disable = await postForm(`/console/users/${admin?.id}/disable`, session, disableCsrf, {})
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
    expect(page).not.toMatch(/<form[^>]+data-wizard-ready/)
    expect(page).toContain("data-wizard-next hidden")
    expect(page).toMatch(/data-wizard-submit(?! hidden)/)
    expect(page.match(/data-wizard-step="[0-3]"/g)).toHaveLength(4)
  })

  it("creates an API prerequisite and returns to the application wizard", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    await env.DB.prepare("UPDATE oauth_resources SET enabled = 0").run()
    try {
      const prerequisite = await SELF.fetch(`${ISSUER}/console/clients/new`, {
        headers: { cookie: `__Host-keyforge_session=${session}` },
      })
      const prerequisiteHtml = await prerequisite.text()
      expect(prerequisiteHtml).not.toContain(
        '<form method="post" action="/console/clients" data-console-wizard',
      )
      expect(prerequisiteHtml).toContain(
        "/console/resources/new?return_to=%2Fconsole%2Fclients%2Fnew",
      )
      expect(prerequisiteHtml).toContain("Back to applications")

      const resourceForm = await SELF.fetch(
        `${ISSUER}/console/resources/new?return_to=%2Fconsole%2Fclients%2Fnew`,
        { headers: { cookie: `__Host-keyforge_session=${session}` } },
      )
      const csrf = cookieValue(resourceForm.headers.getSetCookie(), "__Host-keyforge_csrf")
      const created = await postForm("/console/resources", session, csrf, {
        resource_uri: "https://api.prerequisite.example",
        name: "Prerequisite API",
        allowed_scopes: "openid\nprofile\nemail\noffline_access\napi.read",
        return_to: "/console/clients/new",
      })
      expect(created.status).toBe(302)
      const createdLocation = new URL(created.headers.get("location") ?? "", ISSUER)
      expect(createdLocation.pathname).toBe("/console/clients/new")
      expect(createdLocation.searchParams.get("flash")).toBe("resource_created")
      expect(createdLocation.searchParams.get("clear_draft")).toBe("keyforge:form:resource:new")
      const wizard = await SELF.fetch(
        `${ISSUER}${createdLocation.pathname}${createdLocation.search}`,
        { headers: { cookie: `__Host-keyforge_session=${session}` } },
      )
      const wizardHtml = await wizard.text()
      expect(wizardHtml).toMatch(
        /name="allowed_resources" value="https:\/\/api\.prerequisite\.example"[^>]+ checked/,
      )
    } finally {
      await env.DB.prepare("UPDATE oauth_resources SET enabled = 1").run()
    }
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
    const secretPage = await res.text()
    expect(secretPage).toContain("Client secret")
    expect(secretPage).toContain("data-copy-source")
    expect(secretPage).toContain("data-copy-value")
    expect(secretPage).toContain('data-copy-success="Client secret copied."')
    expect(secretPage).toContain("data-copy-value data-copy-success")
    expect(secretPage).toContain(" hidden>Copy</button>")
    expect(secretPage).toContain('data-draft-clear="keyforge:form:client:new"')
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
    expect(page).toContain('data-initial-step="1"')
    expect(page).toContain("data-error-summary")
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
    const res = await postForm("/console/clients/cx_draft_edit/access", session, csrf, {
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
    expect(page).toContain('aria-label="Application sections"')
    expect(page).toContain('aria-current="page">Access</a>')
    expect(page).toContain("Original client")
    expect(page).toContain("openid\napi.read")
    expect(page).toContain('value="https://not-selected.example"')
    expect(await getClientById(env, "cx_draft_edit")).toMatchObject({
      name: "Original client",

      defaultResource: "https://api.pangda.app",
    })
  })
  it("shows only selected disabled APIs on the Access tab", async () => {
    await createClient(
      env,
      {
        clientId: "cx_disabled_resource",
        name: "Disabled resource client",
        type: "public",
        clientKind: "application",
        redirectUris: ["https://disabled.example/callback"],
        allowedScopes: ["openid", "api.read"],
        allowedGrantTypes: ["authorization_code"],
        allowedResources: ["https://api.pangda.app"],
        defaultResource: "https://api.pangda.app",
        requirePkce: true,
      },
      null,
    )
    await env.DB.prepare("UPDATE oauth_resources SET enabled = 0 WHERE resource_uri IN (?, ?)")
      .bind("https://api.pangda.app", "https://admin.pangda.app")
      .run()
    try {
      const session = await loginAs("admin", "test-admin-password-2026")
      const response = await SELF.fetch(
        `${ISSUER}/console/clients/cx_disabled_resource?view=access`,
        { headers: { cookie: `__Host-keyforge_session=${session}` } },
      )
      const html = await response.text()
      expect(html).toContain('value="https://api.pangda.app"')
      expect(html).toContain("Disabled")
      expect(html).not.toContain('value="https://admin.pangda.app"')
    } finally {
      await env.DB.prepare("UPDATE oauth_resources SET enabled = 1 WHERE resource_uri IN (?, ?)")
        .bind("https://api.pangda.app", "https://admin.pangda.app")
        .run()
    }
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

    const disableReview = await SELF.fetch(`${ISSUER}/console/clients/cx_manage/disable`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(disableReview.status).toBe(200)
    const disablePage = await disableReview.text()
    expect(disablePage).toContain("Disable application?")
    expect(disablePage).not.toContain('name="confirmation"')
    const disableCsrf = cookieValue(disableReview.headers.getSetCookie(), "__Host-keyforge_csrf")
    await postForm("/console/clients/cx_manage/disable", session, disableCsrf, {})
    expect((await getClientById(env, "cx_manage"))?.enabled).toBe(false)

    const confirmation = await SELF.fetch(`${ISSUER}/console/clients/cx_manage/delete`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(confirmation.status).toBe(200)
    expect(await confirmation.text()).toContain("Delete application?")

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

  it("preserves typed API form errors", async () => {
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    const unsafe = await postForm("/console/resources", session, csrf, {
      resource_uri: "javascript:alert(1)",
      name: "Draft API",
      allowed_scopes: "openid\napi.read",
      return_to: "/console/clients/new",
    })
    expect(unsafe.status).toBe(400)
    const unsafeHtml = await unsafe.text()
    expect(unsafeHtml).toContain('value="javascript:alert(1)"')
    expect(unsafeHtml).toContain('value="Draft API"')
    expect(unsafeHtml).toContain('aria-invalid="true"')
    expect(unsafeHtml).toContain('aria-describedby="resource_uri-error"')
    expect(unsafeHtml).toContain('name="return_to" value="/console/clients/new"')

    const edit = await postForm(
      `/console/resources/${encodeURIComponent("https://api.pangda.app")}`,
      session,
      csrf,
      { name: "", allowed_scopes: "openid", enabled: "1" },
    )
    expect(edit.status).toBe(400)
    const editHtml = await edit.text()
    expect(editHtml).toContain("API names cannot be empty")
    expect(editHtml).toContain('aria-describedby="name-error"')
  })

  it("reviews a console device revocation before mutation", async () => {
    const started = await SELF.fetch(`${ISSUER}/oauth/device_authorization`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "pangda_cli",
        scope: "openid api.read",
        resource: "https://api.pangda.app",
      }).toString(),
    })
    expect(started.status).toBe(200)
    const row = await env.DB.prepare(
      "SELECT id, status FROM device_authorization_sessions ORDER BY created_at DESC LIMIT 1",
    ).first<{ id: string; status: string }>()
    expect(row).not.toBeNull()
    if (row === null) return
    const session = await loginAs("admin", "test-admin-password-2026")
    const list = await SELF.fetch(`${ISSUER}/console/devices`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    const listHtml = await list.text()
    expect(listHtml).toContain(`/console/devices/${row.id}/revoke`)
    expect(listHtml).not.toContain(`action="/console/devices/${row.id}/revoke"`)
    const review = await SELF.fetch(`${ISSUER}/console/devices/${row.id}/revoke`, {
      headers: { cookie: `__Host-keyforge_session=${session}` },
    })
    expect(review.status).toBe(200)
    const reviewHtml = await review.text()
    expect(reviewHtml).toContain(`action="/console/devices/${row.id}/revoke"`)
    expect(reviewHtml).toContain("api.read")
    expect(
      (
        await env.DB.prepare("SELECT status FROM device_authorization_sessions WHERE id = ?")
          .bind(row.id)
          .first<{ status: string }>()
      )?.status,
    ).toBe("pending")
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

  it("requires the exact resource URI before deleting an API", async () => {
    const resourceUri = "https://api.console.delete.test"
    const session = await loginAs("admin", "test-admin-password-2026")
    const csrf = await consoleCsrf(session)
    expect(
      (
        await postForm("/console/resources", session, csrf, {
          resource_uri: resourceUri,
          name: "Console Delete API",
          allowed_scopes: "api.read",
        })
      ).status,
    ).toBe(302)
    const encoded = encodeURIComponent(resourceUri)
    const cookie = `__Host-keyforge_session=${session}`
    const edit = await SELF.fetch(`${ISSUER}/console/resources/${encoded}`, {
      headers: { cookie },
    })
    expect(edit.status).toBe(200)
    expect(await edit.text()).toContain(`/console/resources/${encoded}/delete`)

    const confirmation = await SELF.fetch(`${ISSUER}/console/resources/${encoded}/delete`, {
      headers: { cookie },
    })
    expect(confirmation.status).toBe(200)
    const confirmationHtml = await confirmation.text()
    expect(confirmationHtml).toContain("Delete API?")
    expect(confirmationHtml).toContain(`Type ${resourceUri} to confirm`)

    const mismatch = await postForm(`/console/resources/${encoded}/delete`, session, csrf, {
      confirmation: "https://wrong.example",
    })
    expect(mismatch.status).toBe(400)
    expect(await mismatch.text()).toContain("The resource URI did not match. Nothing was deleted.")
    expect(await getResourceByUri(env, resourceUri)).not.toBeNull()

    const deleted = await postForm(`/console/resources/${encoded}/delete`, session, csrf, {
      confirmation: resourceUri,
    })
    expect(deleted.status).toBe(302)
    expect(deleted.headers.get("location")).toContain("flash=resource_deleted")
    expect(await getResourceByUri(env, resourceUri)).toBeNull()
    const list = await SELF.fetch(`${ISSUER}/console/resources?flash=resource_deleted`, {
      headers: { cookie },
    })
    expect(await list.text()).toContain("Resource deleted.")
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
