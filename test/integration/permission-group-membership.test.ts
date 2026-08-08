import { env, SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { setUserPassword } from "../../src/auth/password"
import { getSessionByToken } from "../../src/auth/session"
import { removeUserFromPermissionGroup } from "../../src/db/queries/group-memberships"
import { getPermissionGroupAccess } from "../../src/db/queries/permission-group-access"
import {
  createGroup,
  createUser,
  deleteGroup,
  getGroupByName,
  getUserByEmail,
  getUserGroupNames,
  setUserGroups,
  updateGroup,
} from "../../src/db/queries/users"

const ISSUER = "https://auth.pangda.app"

function cookieValue(setCookies: readonly string[], name: string): string {
  for (const cookie of setCookies) {
    if (cookie.startsWith(`${name}=`)) {
      return cookie.slice(name.length + 1).split(";")[0] ?? ""
    }
  }
  return ""
}

async function loginAs(login: string, password: string): Promise<string> {
  const page = await SELF.fetch(`${ISSUER}/login`)
  const csrf = cookieValue(page.headers.getSetCookie(), "__Host-keyforge_csrf")
  const response = await SELF.fetch(`${ISSUER}/login`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({
      email: login,
      password,
      csrf_token: csrf,
    }).toString(),
    redirect: "manual",
  })
  return cookieValue(response.headers.getSetCookie(), "__Host-keyforge_session")
}

async function pageCsrf(path: string, session: string): Promise<{ csrf: string; html: string }> {
  const response = await SELF.fetch(`${ISSUER}${path}`, {
    headers: { cookie: `__Host-keyforge_session=${session}` },
  })
  return {
    csrf: cookieValue(response.headers.getSetCookie(), "__Host-keyforge_csrf"),
    html: await response.text(),
  }
}

async function postForm(
  path: string,
  session: string,
  csrf: string,
  values: Record<string, string> = {},
): Promise<Response> {
  return SELF.fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: `__Host-keyforge_session=${session}; __Host-keyforge_csrf=${csrf}`,
    },
    body: new URLSearchParams({ csrf_token: csrf, ...values }).toString(),
    redirect: "manual",
  })
}

async function requestCount(userId: string, groupId: string): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM group_membership_requests WHERE user_id = ? AND group_id = ?",
  )
    .bind(userId, groupId)
    .first<{ count: number }>()
  return row?.count ?? 0
}

describe("permission-group membership workflow", () => {
  it("keeps every account in the protected all group", async () => {
    const universalGroup = await getGroupByName(env, "all")
    const admins = await getGroupByName(env, "admins")
    expect(universalGroup).not.toBeNull()
    expect(admins).not.toBeNull()

    const user = await createUser(env, {
      email: "universal.membership@example.test",
      alias: "universalmembership",
    })
    expect(await getUserGroupNames(env, user.id)).toContain("all")

    await setUserGroups(env, user.id, [])
    expect(await getUserGroupNames(env, user.id)).toEqual(["all"])
    expect(await removeUserFromPermissionGroup(env, universalGroup?.id ?? "missing", user.id)).toBe(
      "protected",
    )
    expect(
      await updateGroup(
        env,
        universalGroup?.id ?? "missing",
        "renamed-all",
        universalGroup?.description ?? null,
      ),
    ).toBe("protected")
    expect(await deleteGroup(env, universalGroup?.id ?? "missing")).toBe("protected")

    expect(await getPermissionGroupAccess(env, universalGroup?.id ?? "missing")).toEqual(
      expect.objectContaining({ clientIds: expect.arrayContaining(["pangda_admin"]) }),
    )
    expect(await getPermissionGroupAccess(env, admins?.id ?? "missing")).toEqual(
      expect.objectContaining({
        clientIds: expect.not.arrayContaining(["pangda_admin"]),
        resourceUris: expect.arrayContaining(["https://admin.pangda.app"]),
      }),
    )
  })

  it("lets users request groups and administrators review or directly manage membership", async () => {
    const group = await createGroup(env, "membership-reviewers", "Reviews controlled releases")
    const applicant = await createUser(env, {
      email: "membership.applicant@example.test",
      alias: "membershipapplicant",
      name: "Membership Applicant",
      emailVerified: true,
    })
    await setUserPassword(env, applicant.id, "membership-password-2026")

    const applicantSession = await loginAs(applicant.alias, "membership-password-2026")
    const accountPage = await pageCsrf("/?section=groups", applicantSession)
    expect(accountPage.html).toContain("Your permission groups")
    expect(accountPage.html).toContain('action="/account/groups/request"')
    expect(accountPage.html).toContain("data-search-picker")
    expect(accountPage.html).toContain(`value="${group.id}"`)
    expect(accountPage.html).not.toContain('value="grp_seed_admins"')

    const requested = await postForm(
      "/account/groups/request",
      applicantSession,
      accountPage.csrf,
      {
        group_id: group.id,
      },
    )
    expect(requested.headers.get("location")).toBe(
      "/?section=groups&notice=group_request_submitted",
    )
    expect(await requestCount(applicant.id, group.id)).toBe(1)

    const pendingPage = await pageCsrf("/?section=groups", applicantSession)
    expect(pendingPage.html).toContain("Pending review")
    expect(pendingPage.html).toContain(`/account/groups/requests/${group.id}/cancel`)
    const duplicate = await postForm(
      "/account/groups/request",
      applicantSession,
      pendingPage.csrf,
      { group_id: group.id },
    )
    expect(duplicate.headers.get("location")).toBe("/?section=groups&notice=group_request_pending")
    expect(await requestCount(applicant.id, group.id)).toBe(1)

    const admins = await getGroupByName(env, "admins")
    expect(admins).not.toBeNull()
    const protectedRequest = await postForm(
      "/account/groups/request",
      applicantSession,
      pendingPage.csrf,
      { group_id: admins?.id ?? "missing" },
    )
    expect(protectedRequest.headers.get("location")).toBe(
      "/?section=groups&notice=group_request_unavailable",
    )

    const adminSession = await loginAs("admin", "test-admin-password-2026")
    const membersPath = `/console/groups/${group.id}?view=members&q=membershipapplicant`
    const reviewPage = await pageCsrf(membersPath, adminSession)
    expect(reviewPage.html).toContain("Pending requests")
    expect(reviewPage.html).toContain(
      `/console/groups/${group.id}/requests/${applicant.id}/approve`,
    )
    expect(reviewPage.html).toContain("Search users to add")

    const approved = await postForm(
      `/console/groups/${group.id}/requests/${applicant.id}/approve`,
      adminSession,
      reviewPage.csrf,
    )
    expect(approved.headers.get("location")).toContain("flash=group_request_approved")
    expect(await getUserGroupNames(env, applicant.id)).toContain(group.name)
    expect(await requestCount(applicant.id, group.id)).toBe(0)
    const replayedApproval = await postForm(
      `/console/groups/${group.id}/requests/${applicant.id}/approve`,
      adminSession,
      reviewPage.csrf,
    )
    expect(replayedApproval.headers.get("location")).toContain("flash=not_found")

    const memberPage = await pageCsrf(`/console/groups/${group.id}?view=members`, adminSession)
    expect(memberPage.html).toContain(`/console/groups/${group.id}/members/${applicant.id}/remove`)
    const removed = await postForm(
      `/console/groups/${group.id}/members/${applicant.id}/remove`,
      adminSession,
      memberPage.csrf,
    )
    expect(removed.headers.get("location")).toContain("flash=group_member_removed")
    expect(await getUserGroupNames(env, applicant.id)).not.toContain(group.name)

    const candidatePage = await pageCsrf(membersPath, adminSession)
    expect(candidatePage.html).toContain(`name="user_id" value="${applicant.id}"`)
    const added = await postForm(
      `/console/groups/${group.id}/members`,
      adminSession,
      candidatePage.csrf,
      {
        user_id: applicant.id,
      },
    )
    expect(added.headers.get("location")).toContain("flash=group_member_added")
    expect(await getUserGroupNames(env, applicant.id)).toContain(group.name)

    const finalMemberPage = await pageCsrf(`/console/groups/${group.id}?view=members`, adminSession)
    await postForm(
      `/console/groups/${group.id}/members/${applicant.id}/remove`,
      adminSession,
      finalMemberPage.csrf,
    )
    const requestAgainPage = await pageCsrf("/?section=groups", applicantSession)
    await postForm("/account/groups/request", applicantSession, requestAgainPage.csrf, {
      group_id: group.id,
    })
    const cancelPage = await pageCsrf("/?section=groups", applicantSession)
    const cancelled = await postForm(
      `/account/groups/requests/${group.id}/cancel`,
      applicantSession,
      cancelPage.csrf,
    )
    expect(cancelled.headers.get("location")).toBe(
      "/?section=groups&notice=group_request_cancelled",
    )
    expect(await requestCount(applicant.id, group.id)).toBe(0)

    const thirdRequestPage = await pageCsrf("/?section=groups", applicantSession)
    await postForm("/account/groups/request", applicantSession, thirdRequestPage.csrf, {
      group_id: group.id,
    })
    const rejectPage = await pageCsrf(`/console/groups/${group.id}?view=members`, adminSession)
    const rejected = await postForm(
      `/console/groups/${group.id}/requests/${applicant.id}/reject`,
      adminSession,
      rejectPage.csrf,
    )
    expect(rejected.headers.get("location")).toContain("flash=group_request_rejected")
    expect(await requestCount(applicant.id, group.id)).toBe(0)
    expect(await getUserGroupNames(env, applicant.id)).not.toContain(group.name)
  })

  it("keeps the sole active administrator when membership is managed from a group", async () => {
    const admin = await getUserByEmail(env, "admin")
    const admins = await getGroupByName(env, "admins")
    expect(admin).not.toBeNull()
    expect(admins).not.toBeNull()

    const adminSession = await loginAs("admin", "test-admin-password-2026")
    const memberPage = await pageCsrf(
      `/console/groups/${admins?.id ?? "missing"}?view=members`,
      adminSession,
    )
    const removal = await postForm(
      `/console/groups/${admins?.id ?? "missing"}/members/${admin?.id ?? "missing"}/remove`,
      adminSession,
      memberPage.csrf,
    )
    expect(removal.headers.get("location")).toContain("flash=last_admin")
    expect(await getUserGroupNames(env, admin?.id ?? "missing")).toContain("admins")
  })

  it("revokes existing sessions when direct membership grants administrator access", async () => {
    const promoted = await createUser(env, {
      email: "promoted.admin@example.test",
      alias: "promotedadmin",
      emailVerified: true,
    })
    await setUserPassword(env, promoted.id, "short6")
    const promotedSession = await loginAs(promoted.alias, "short6")
    expect(await getSessionByToken(env, promotedSession)).not.toBeNull()

    const admins = await getGroupByName(env, "admins")
    const adminSession = await loginAs("admin", "test-admin-password-2026")
    const candidates = await pageCsrf(
      `/console/groups/${admins?.id ?? "missing"}?view=members&q=promotedadmin`,
      adminSession,
    )
    const added = await postForm(
      `/console/groups/${admins?.id ?? "missing"}/members`,
      adminSession,
      candidates.csrf,
      { user_id: promoted.id },
    )
    expect(added.headers.get("location")).toContain("flash=group_member_added")
    expect(await getUserGroupNames(env, promoted.id)).toContain("admins")
    expect(await getSessionByToken(env, promotedSession)).toBeNull()
  })
})
