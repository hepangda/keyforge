import { Hono } from "hono"
import { listPasswordCredentials, minimumPasswordLength } from "../auth/password"
import { listSessionsByUser } from "../auth/session"
import { getClientById } from "../db/queries/clients"
import { listConsentsByUser } from "../db/queries/consents"
import { listDeviceRefreshFamiliesForUser } from "../db/queries/tokens"
import { getUserGroupNames } from "../db/queries/users"
import { listCredentialSummaries } from "../db/queries/webauthn"
import { issueCsrfToken } from "../security/csrf"
import type { AppBindings } from "../types/app"
import type { DashboardApp, DashboardData, DashboardSection } from "../views/dashboard"
import { DASHBOARD_SECTIONS, renderDashboard } from "../views/dashboard"

const ADMIN_GROUP = "admins"

function parseSection(raw: string | undefined, isAdmin: boolean): DashboardSection {
  const match = DASHBOARD_SECTIONS.find((candidate) => candidate === raw)
  if (match === undefined || (match === "admin" && !isAdmin)) {
    return "profile"
  }
  return match
}

export const home = new Hono<AppBindings>()

home.get("/", async (c) => {
  const user = c.get("user")
  const session = c.get("session")
  if (user === undefined || session === undefined) {
    return c.redirect("/login")
  }
  const [groups, sessions, passwords, passkeys, consents, deviceFamilies] = await Promise.all([
    getUserGroupNames(c.env, user.id),
    listSessionsByUser(c.env, user.id),
    listPasswordCredentials(c.env, user.id),
    listCredentialSummaries(c.env, user.id),
    listConsentsByUser(c.env, user.id),
    listDeviceRefreshFamiliesForUser(c.env, user.id),
  ])
  const consentGroups = new Map<string, { scopes: Set<string>; resources: Set<string> }>()
  for (const consent of consents) {
    const group = consentGroups.get(consent.clientId) ?? {
      scopes: new Set<string>(),
      resources: new Set<string>(),
    }
    for (const scope of consent.scope.split(" ").filter(Boolean)) group.scopes.add(scope)
    if (consent.resource !== null) group.resources.add(consent.resource)
    consentGroups.set(consent.clientId, group)
  }
  const apps: DashboardApp[] = await Promise.all(
    [...consentGroups.entries()].map(async ([clientId, group]) => {
      const client = await getClientById(c.env, clientId)
      return {
        clientId,
        name: client?.name ?? clientId,
        scopes: [...group.scopes].sort(),
        resources: [...group.resources].sort(),
      }
    }),
  )
  const isAdmin = groups.includes(ADMIN_GROUP)
  const notice = c.req.query("notice")
  const data: DashboardData = {
    csrfToken: issueCsrfToken(c),
    user,
    groups,
    isAdmin,
    sessions: sessions.map((entry) => ({
      id: entry.id,
      authMethod: entry.authMethod,
      passkeyAuthenticated: entry.passkeyAuthenticated,
      createdAt: entry.createdAt,
      lastSeenAt: entry.lastSeenAt,
      expiresAt: entry.expiresAt,
      current: entry.id === session.id,
    })),
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
  return c.html(renderDashboard(data, parseSection(c.req.query("section"), isAdmin)))
})
