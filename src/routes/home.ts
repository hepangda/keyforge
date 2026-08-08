import { Hono } from "hono"
import { listPasswordCredentials, minimumPasswordLength } from "../auth/password"
import { listSessionsByUser } from "../auth/session"
import { listConsentsByUser } from "../db/queries/consents"
import { listPermissionGroupsForUser } from "../db/queries/group-memberships"
import { listDeviceRefreshFamiliesForUser } from "../db/queries/tokens"
import { getUserGroupNames } from "../db/queries/users"
import { listCredentialSummaries } from "../db/queries/webauthn"
import { issueCsrfToken } from "../security/csrf"
import { hasRecentAuthentication } from "../security/recent-auth"
import type { AppBindings } from "../types/app"
import type { DashboardData, DashboardFlow, DashboardSection } from "../views/dashboard"
import { DASHBOARD_FLOWS, DASHBOARD_SECTIONS, renderDashboard } from "../views/dashboard"

const ADMIN_GROUP = "admins"

function parseSection(raw: string | undefined, isAdmin: boolean): DashboardSection {
  const match = DASHBOARD_SECTIONS.find((candidate) => candidate === raw)
  if (match === undefined || (match === "admin" && !isAdmin)) {
    return "profile"
  }
  return match
}
const PROFILE_FLOWS = new Set<DashboardFlow>(["edit-profile", "change-email", "delete-account"])
const LOGIN_METHOD_FLOWS = new Set<DashboardFlow>([
  "add-password",
  "add-passkey",
  "manage-password",
  "manage-passkey",
  "remove-password",
  "remove-passkey",
])
const SESSION_FLOWS = new Set<DashboardFlow>(["revoke-other-sessions"])
const APP_FLOWS = new Set<DashboardFlow>(["revoke-app", "revoke-device"])

function parseFlow(raw: string | undefined, section: DashboardSection): DashboardFlow | null {
  const flow = DASHBOARD_FLOWS.find((candidate) => candidate === raw)
  if (flow === undefined) return null
  if (section === "profile" && PROFILE_FLOWS.has(flow)) return flow
  if (section === "sessions" && SESSION_FLOWS.has(flow)) return flow
  if (section === "apps" && APP_FLOWS.has(flow)) return flow
  if (section === "login-methods" && LOGIN_METHOD_FLOWS.has(flow)) return flow
  return null
}
const RECENT_AUTH_LOGIN_METHOD_FLOWS = new Set<DashboardFlow>([
  "add-password",
  "add-passkey",
  "manage-password",
  "manage-passkey",
  "remove-password",
  "remove-passkey",
])

function reauthHintForFlow(flow: DashboardFlow | null): string | undefined {
  if (flow === "add-password") return "add_password"
  if (flow === "manage-password" || flow === "remove-password") return "manage_password"
  if (flow === "add-passkey") return "add_passkey"
  if (flow === "manage-passkey" || flow === "remove-passkey") return "manage_passkey"
  if (flow === "change-email") return "change_email"
  if (flow === "delete-account") return "delete_account"
  return undefined
}

function reauthenticationRedirect(returnTo: string, hint?: string): string {
  const params = new URLSearchParams({ reauth: "1", return_to: returnTo })
  if (hint !== undefined) params.set("hint", hint)
  return `/login?${params.toString()}`
}

export const home = new Hono<AppBindings>()

home.get("/", async (c) => {
  const user = c.get("user")
  const session = c.get("session")
  if (user === undefined || session === undefined) {
    return c.redirect("/login")
  }
  const groups = await getUserGroupNames(c.env, user.id)
  const isAdmin = groups.includes(ADMIN_GROUP)
  const section = parseSection(c.req.query("section"), isAdmin)
  const flow = parseFlow(c.req.query("flow"), section)
  const targetId = c.req.query("target") ?? null
  let permissionGroups: DashboardData["permissionGroups"] = []
  let passwords: DashboardData["passwords"] = []
  let passkeys: DashboardData["passkeys"] = []
  let sessions: DashboardData["sessions"] = []
  let apps: DashboardData["apps"] = []
  let deviceFamilies: DashboardData["devices"] = []

  if (section === "login-methods") {
    ;[passwords, passkeys] = await Promise.all([
      listPasswordCredentials(c.env, user.id),
      listCredentialSummaries(c.env, user.id),
    ])
  } else if (section === "profile" && (flow === "change-email" || flow === "delete-account")) {
    passwords = await listPasswordCredentials(c.env, user.id)
  }

  const passwordTargetFlow = flow === "manage-password" || flow === "remove-password"
  const passkeyTargetFlow = flow === "manage-passkey" || flow === "remove-passkey"
  if (
    (passwordTargetFlow &&
      (targetId === null || !passwords.some((credential) => credential.id === targetId))) ||
    (passkeyTargetFlow &&
      (targetId === null || !passkeys.some((credential) => credential.id === targetId)))
  ) {
    return c.redirect("/?section=login-methods&notice=not_found")
  }
  const needsRecentAuthentication =
    (flow !== null && RECENT_AUTH_LOGIN_METHOD_FLOWS.has(flow)) ||
    (passwords.length === 0 && (flow === "change-email" || flow === "delete-account"))
  if (needsRecentAuthentication && !hasRecentAuthentication(session)) {
    const url = new URL(c.req.url)
    return c.redirect(
      reauthenticationRedirect(`${url.pathname}${url.search}`, reauthHintForFlow(flow)),
    )
  }
  if (section === "groups") {
    permissionGroups = await listPermissionGroupsForUser(c.env, user.id)
  } else if (section === "sessions") {
    sessions = (await listSessionsByUser(c.env, user.id)).map((entry) => ({
      id: entry.id,
      authMethod: entry.authMethod,
      passkeyAuthenticated: entry.passkeyAuthenticated,
      createdAt: entry.createdAt,
      lastSeenAt: entry.lastSeenAt,
      expiresAt: entry.expiresAt,
      current: entry.id === session.id,
    }))
  } else if (section === "apps") {
    const [consents, devices] = await Promise.all([
      listConsentsByUser(c.env, user.id),
      listDeviceRefreshFamiliesForUser(c.env, user.id),
    ])
    deviceFamilies = devices
    const consentGroups = new Map<
      string,
      { name: string; scopes: Set<string>; resources: Set<string> }
    >()
    for (const consent of consents) {
      const group = consentGroups.get(consent.clientId) ?? {
        name: consent.clientName,
        scopes: new Set<string>(),
        resources: new Set<string>(),
      }
      for (const scope of consent.scope.split(" ").filter(Boolean)) group.scopes.add(scope)
      if (consent.resource !== null) group.resources.add(consent.resource)
      consentGroups.set(consent.clientId, group)
    }
    apps = [...consentGroups.entries()].map(([clientId, group]) => ({
      clientId,
      name: group.name,
      scopes: [...group.scopes].sort(),
      resources: [...group.resources].sort(),
    }))
  }
  if (
    (flow === "revoke-app" &&
      (targetId === null || !apps.some((app) => app.clientId === targetId))) ||
    (flow === "revoke-device" &&
      (targetId === null || !deviceFamilies.some((device) => device.familyId === targetId)))
  ) {
    return c.redirect("/?section=apps&notice=not_found")
  }

  const notice = c.req.query("notice")
  const data: DashboardData = {
    i18n: c.get("i18n"),
    csrfToken: issueCsrfToken(c),
    user,
    groups,
    permissionGroups,
    isAdmin,
    sessions,
    passwords,
    passkeys: passkeys.map((entry) => ({
      id: entry.id,
      name: entry.name,
      createdAt: entry.createdAt,
      lastUsedAt: entry.lastUsedAt,
    })),
    apps,
    devices: deviceFamilies,
    passwordMinimum: minimumPasswordLength(isAdmin),
    ...(notice === undefined ? {} : { notice }),
  }
  return c.html(
    renderDashboard(data, section, {
      flow,
      targetId,
    }),
  )
})
