import type { AuthMethod, User } from "../types/domain"
import { appShell, escapeHtml, icons } from "./layout"

export type DashboardSessionRow = {
  readonly id: string
  readonly authMethod: AuthMethod
  readonly passkeyAuthenticated: boolean
  readonly createdAt: number
  readonly lastSeenAt: number
  readonly expiresAt: number
  readonly current: boolean
}

export type DashboardPasskey = {
  readonly id: string
  readonly name: string | null
  readonly createdAt: number
  readonly lastUsedAt: number | null
}

export type DashboardIdentity = {
  readonly provider: string
  readonly email: string | null
}

export type DashboardApp = {
  readonly clientId: string
  readonly name: string
  readonly scopes: readonly string[]
  readonly resources: readonly string[]
}

export type DashboardDevice = {
  readonly familyId: string
  readonly clientId: string
  readonly clientName: string
  readonly resource: string
  readonly createdAt: number
  readonly lastRotatedAt: number
  readonly expiresAt: number
}

export type DashboardData = {
  readonly csrfToken: string
  readonly user: User
  readonly groups: readonly string[]
  readonly isAdmin: boolean
  readonly sessions: readonly DashboardSessionRow[]
  readonly passkeys: readonly DashboardPasskey[]
  readonly identities: readonly DashboardIdentity[]
  readonly apps: readonly DashboardApp[]
  readonly devices: readonly DashboardDevice[]
  readonly connectableProviders: readonly string[]
  readonly hasPassword: boolean
  readonly notice?: string
}

export const DASHBOARD_SECTIONS = [
  "profile",
  "sessions",
  "apps",
  "identities",
  "passkeys",
  "admin",
] as const
export type DashboardSection = (typeof DASHBOARD_SECTIONS)[number]

const NAV_ITEMS: readonly { readonly section: DashboardSection; readonly label: string }[] = [
  { section: "profile", label: "Profile" },
  { section: "sessions", label: "Active sessions" },
  { section: "apps", label: "Authorized apps" },
  { section: "identities", label: "Connected accounts" },
  { section: "passkeys", label: "Passkeys" },
  { section: "admin", label: "Administration" },
]

const AUTH_METHOD_LABELS: Record<AuthMethod, string> = {
  password: "Password",
  magic_link: "Magic link",
  passkey: "Passkey",
  github: "GitHub",
  google: "Google",
}

const PROVIDER_LABELS: Record<string, string> = { github: "GitHub", google: "Google" }

function providerLabel(provider: string): string {
  return PROVIDER_LABELS[provider] ?? provider
}

function formatDate(epochSeconds: number): string {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(new Date(epochSeconds * 1000))
}

function initialsOf(value: string): string {
  const base = value.includes("@") ? (value.split("@")[0] ?? value) : value
  const parts = base
    .trim()
    .split(/[\s._-]+/)
    .filter(Boolean)
  const a = parts[0] ?? ""
  const b = parts[1] ?? ""
  const chars = b ? (a[0] ?? "") + (b[0] ?? "") : a.slice(0, 2)
  return (chars || "?").toUpperCase()
}

function csrfField(token: string): string {
  return `<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">`
}

function renderProfile(data: DashboardData): string {
  const { user, groups } = data
  const displayName = user.name ?? user.email
  const typeLabel = user.userType === "internal" ? "Internal" : "External"
  const sub = user.name ? escapeHtml(user.email) : `${typeLabel} account`
  const avatar =
    user.picture === null
      ? `<div class="avatar avatar--fallback" aria-hidden="true">${escapeHtml(initialsOf(displayName))}</div>`
      : `<img class="avatar" src="${escapeHtml(user.picture)}" alt="" referrerpolicy="no-referrer">`
  const emailBadge = user.emailVerified
    ? `<span class="badge badge--ok"><span class="badge__dot"></span>Verified</span>`
    : `<span class="badge badge--warn"><span class="badge__dot"></span>Unverified</span>`
  const groupList = groups.length === 0 ? "—" : groups.map((g) => escapeHtml(g)).join(", ")

  const verifyEmail = user.emailVerified
    ? ""
    : `<form method="post" action="/account/email/verify">
      ${csrfField(data.csrfToken)}
      <button class="btn btn--ghost btn--sm" type="submit">Send verification email</button>
    </form>`
  const currentPassword = data.hasPassword
    ? `<label class="field"><span class="field__label">Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>`
    : `<div class="callout">You're adding a password to an account that currently signs in another way.</div>`
  const emailChangePassword = data.hasPassword
    ? `<label class="field"><span class="field__label">Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>`
    : `<div class="callout">For accounts without a password, this action requires a recent sign-in.</div>`

  return `<section class="dash-panel" id="profile">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Profile</h2>
      <p class="dash-panel__desc">Your personal information and account status.</p>
    </div>
  </div>
  <div class="dash-panel__body">
    <div class="identity">
      ${avatar}
      <div class="identity__body">
        <div class="identity__name">${escapeHtml(displayName)}</div>
        <div class="identity__sub">${sub}</div>
      </div>
    </div>
    <div class="meta">
      <div class="meta__row"><span class="meta__key">Email</span><span class="meta__val">${escapeHtml(user.email)}</span></div>
      <div class="meta__row"><span class="meta__key">Verification</span><span class="meta__val">${emailBadge}</span></div>
      <div class="meta__row"><span class="meta__key">Account type</span><span class="meta__val">${typeLabel}</span></div>
      <div class="meta__row"><span class="meta__key">Groups</span><span class="meta__val">${groupList}</span></div>
      <div class="meta__row"><span class="meta__key">Member since</span><span class="meta__val mono">${escapeHtml(formatDate(user.createdAt))}</span></div>
    </div>
    <div class="settings-grid">
      <form method="post" action="/account/profile" class="setting-card">
        ${csrfField(data.csrfToken)}
        <div><h3>Display name</h3><p>Shown in KeyForge and shared with approved applications.</p></div>
        <label class="field"><span class="field__label">Name</span><input class="input" name="name" maxlength="120" value="${escapeHtml(user.name ?? "")}" autocomplete="name"></label>
        <button class="btn btn--ghost btn--sm" type="submit">Save profile</button>
      </form>
      <div class="setting-card">
        <div><h3>Email verification</h3><p>${user.emailVerified ? "This address has been verified." : "Verify this address before applications treat it as confirmed."}</p></div>
        ${verifyEmail}
      </div>
      <form method="post" action="/account/email/change" class="setting-card">
        ${csrfField(data.csrfToken)}
        <div><h3>Change email</h3><p>We will confirm the new address before changing your sign-in ID.</p></div>
        <label class="field"><span class="field__label">New email</span><input class="input" type="email" name="new_email" autocomplete="email" maxlength="254" required></label>
        ${emailChangePassword}
        <button class="btn btn--ghost btn--sm" type="submit">Send confirmation</button>
      </form>
      <form method="post" action="/account/password" class="setting-card">
        ${csrfField(data.csrfToken)}
        <div><h3>${data.hasPassword ? "Change password" : "Add a password"}</h3><p>Use at least 12 characters and keep it unique to this account.</p></div>
        ${currentPassword}
        <label class="field"><span class="field__label">New password</span><input class="input" type="password" name="new_password" minlength="12" maxlength="128" autocomplete="new-password" required></label>
        <label class="field"><span class="field__label">Confirm new password</span><input class="input" type="password" name="new_password_confirm" minlength="12" maxlength="128" autocomplete="new-password" required></label>
        <button class="btn btn--ghost btn--sm" type="submit">${data.hasPassword ? "Change password" : "Add password"}</button>
      </form>
      <form method="post" action="/account/delete" class="setting-card setting-card--danger">
        ${csrfField(data.csrfToken)}
        <div><h3>Delete account</h3><p>Permanently removes your identity, sessions, credentials, and application grants.</p></div>
        <label class="field"><span class="field__label">Type ${escapeHtml(user.email)} to confirm</span><input class="input" name="confirmation" autocomplete="off" required></label>
        ${data.hasPassword ? `<label class="field"><span class="field__label">Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>` : ""}
        <button class="btn btn--danger btn--sm" type="submit">Delete account</button>
      </form>
    </div>
  </div>
</section>`
}

function renderSessions(data: DashboardData): string {
  const rows = data.sessions
    .map((session) => {
      const label = AUTH_METHOD_LABELS[session.authMethod]
      const current = session.current ? ' <span class="dash-item__current">This device</span>' : ""
      const action = session.current
        ? ""
        : `<form method="post" action="/account/sessions/${escapeHtml(session.id)}/revoke">
        ${csrfField(data.csrfToken)}
        <button type="submit" class="btn btn--ghost btn--sm">Sign out</button>
      </form>`
      return `<li class="dash-list__item">
      <div class="dash-item__main">
        <div class="dash-item__title">${escapeHtml(label)}${current}</div>
        <div class="dash-item__meta">
          <span>Started <span class="mono">${formatDate(session.createdAt)}</span></span>
          <span aria-hidden="true">·</span>
          <span>Last active <span class="mono">${formatDate(session.lastSeenAt)}</span></span>
          <span aria-hidden="true">·</span>
          <span>Expires <span class="mono">${formatDate(session.expiresAt)}</span></span>
        </div>
      </div>
      <div class="dash-item__actions">${action}</div>
    </li>`
    })
    .join("\n")

  const others = data.sessions.filter((session) => !session.current).length
  const signOutOthers =
    others === 0
      ? ""
      : `<div class="dash-panel__foot dash-panel__foot--end">
    <form method="post" action="/account/sessions/revoke-others">
      ${csrfField(data.csrfToken)}
      <button type="submit" class="btn btn--ghost btn--sm">Sign out all other sessions</button>
    </form>
  </div>`

  return `<section class="dash-panel" id="sessions">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Active sessions</h2>
      <p class="dash-panel__desc">Devices and browsers currently signed in to your account.</p>
    </div>
  </div>
  <ul class="dash-list">${rows}</ul>
  ${signOutOthers}
</section>`
}

function renderApps(data: DashboardData): string {
  if (data.apps.length === 0) {
    return `<section class="dash-panel" id="apps">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Authorized apps</h2>
      <p class="dash-panel__desc">Applications you have granted access to your account.</p>
    </div>
  </div>
  <div class="dash-list">
    <div class="dash-list__item--empty">No applications currently have access to your account.</div>
  </div>
</section>`
  }

  const rows = data.apps
    .map((app) => {
      const scopes = app.scopes.map((scope) => escapeHtml(scope)).join(", ")
      const resources = app.resources.map((resource) => escapeHtml(resource)).join(", ")
      return `<li class="dash-list__item">
      <div class="dash-item__main">
        <div class="dash-item__title">${escapeHtml(app.name)}</div>
        <div class="dash-item__meta">
          <span class="dash-item__icon">${icons.key}</span>
          <span class="mono">${scopes}</span>
        </div>
        <div class="dash-item__meta">Resources: <span class="mono">${resources}</span></div>
      </div>
      <div class="dash-item__actions">
        <form method="post" action="/account/apps/${encodeURIComponent(app.clientId)}/revoke">
          ${csrfField(data.csrfToken)}
          <button type="submit" class="btn btn--ghost btn--sm">Revoke all access</button>
        </form>
      </div>
    </li>`
    })
    .join("\n")

  return `<section class="dash-panel" id="apps">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Authorized apps</h2>
      <p class="dash-panel__desc">Applications you have granted access to your account.</p>
    </div>
  </div>
  <ul class="dash-list">${rows}</ul>
</section>`
}

function renderAuthorizedDevices(data: DashboardData): string {
  const rows =
    data.devices.length === 0
      ? '<li class="dash-list__item--empty">No independently authorized CLI or device sessions.</li>'
      : data.devices
          .map(
            (device) => `<li class="dash-list__item">
      <div class="dash-item__main">
        <div class="dash-item__title">${escapeHtml(device.clientName)}</div>
        <div class="dash-item__meta"><span class="mono">${escapeHtml(device.resource)}</span> · Last used ${formatDate(device.lastRotatedAt)} · Expires ${formatDate(device.expiresAt)}</div>
      </div>
      <div class="dash-item__actions">
        <form method="post" action="/account/devices/${encodeURIComponent(device.familyId)}/revoke">
          ${csrfField(data.csrfToken)}
          <button type="submit" class="btn btn--ghost btn--sm">Revoke device</button>
        </form>
      </div>
    </li>`,
          )
          .join("\n")
  return `<section class="dash-panel" id="authorized-devices">
  <div class="dash-panel__head"><div><h2 class="dash-panel__title">Authorized CLI and devices</h2><p class="dash-panel__desc">Refresh access issued independently to a device. Revoke one without signing out everything else.</p></div></div>
  <ul class="dash-list">${rows}</ul>
</section>`
}

function renderIdentities(data: DashboardData): string {
  const connected =
    data.identities.length === 0
      ? '<li class="dash-list__item--empty">No social accounts connected.</li>'
      : data.identities
          .map(
            (identity) => `<li class="dash-list__item">
      <div class="dash-item__main">
        <div class="dash-item__title">${escapeHtml(providerLabel(identity.provider))}</div>
        <div class="dash-item__meta">${escapeHtml(identity.email ?? "")}</div>
      </div>
      <div class="dash-item__actions"><form method="post" action="/account/identities/${escapeHtml(identity.provider)}/unlink">${csrfField(data.csrfToken)}<button class="btn btn--ghost btn--sm" type="submit">Disconnect</button></form></div>
    </li>`,
          )
          .join("\n")

  const connect =
    data.connectableProviders.length === 0
      ? ""
      : `<div class="dash-panel__foot">
      <div class="dash-chip-row">
        ${data.connectableProviders
          .map(
            (provider) =>
              `<form method="post" action="/account/identities/${escapeHtml(provider)}/connect">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Connect ${escapeHtml(providerLabel(provider))}</button></form>`,
          )
          .join("")}
      </div>
    </div>`

  return `<section class="dash-panel" id="identities">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Connected accounts</h2>
      <p class="dash-panel__desc">Social and enterprise identities linked to this account.</p>
    </div>
  </div>
  <ul class="dash-list">${connected}</ul>
  ${connect}
</section>`
}

function renderPasskeys(data: DashboardData): string {
  const rows =
    data.passkeys.length === 0
      ? '<li class="dash-list__item--empty">No passkeys registered yet. Add one to sign in with your device unlock.</li>'
      : data.passkeys
          .map(
            (passkey) => `<li class="dash-list__item">
      <div class="dash-item__main">
        <div class="dash-item__title">${escapeHtml(passkey.name ?? "Passkey")}</div>
        <div class="dash-item__meta">Added <span class="mono">${formatDate(passkey.createdAt)}</span>${passkey.lastUsedAt === null ? "" : ` · Last used <span class="mono">${formatDate(passkey.lastUsedAt)}</span>`}</div>
      </div>
      <div class="credential-actions">
        <form method="post" action="/account/passkeys/${escapeHtml(passkey.id)}/rename" class="credential-rename">
          ${csrfField(data.csrfToken)}
          <input class="input" name="name" maxlength="80" aria-label="Passkey name" placeholder="Passkey name" value="${escapeHtml(passkey.name ?? "")}">
          <button class="btn btn--ghost btn--sm" type="submit">Rename</button>
        </form>
        <form method="post" action="/account/passkeys/${escapeHtml(passkey.id)}/delete">
          ${csrfField(data.csrfToken)}
          <button class="btn btn--ghost btn--sm" type="submit">Delete</button>
        </form>
      </div>
    </li>`,
          )
          .join("\n")
  return `<section class="dash-panel" id="passkeys">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Passkeys</h2>
      <p class="dash-panel__desc">Phishing-resistant sign-in protected by your device PIN or biometrics.</p>
    </div>
    <button class="btn btn--primary btn--sm btn--auto" type="button" data-passkey-register data-csrf="${escapeHtml(data.csrfToken)}">Add passkey</button>
  </div>
  <ul class="dash-list">${rows}</ul>
  <div class="dash-panel__foot"><p class="inline-status" data-passkey-status role="status" hidden></p></div>
  <script src="/assets/account.js" defer></script>
</section>`
}

function renderAdmin(isAdmin: boolean): string {
  if (!isAdmin) return ""

  return `<section class="dash-panel" id="admin">
  <div class="dash-panel__head">
    <div>
      <h2 class="dash-panel__title">Administration</h2>
      <p class="dash-panel__desc">You have administrator access.</p>
    </div>
    <div class="dash-item__actions">
      <a href="/console" class="btn btn--primary btn--sm">Open admin area</a>
    </div>
  </div>
</section>`
}

function renderSection(data: DashboardData, section: DashboardSection): string {
  switch (section) {
    case "profile":
      return renderProfile(data)
    case "sessions":
      return renderSessions(data)
    case "apps":
      return `${renderApps(data)}${renderAuthorizedDevices(data)}`
    case "identities":
      return renderIdentities(data)
    case "passkeys":
      return renderPasskeys(data)
    case "admin":
      return renderAdmin(data.isAdmin)
  }
}

export function renderDashboard(data: DashboardData, section: DashboardSection): string {
  const displayName = data.user.name ?? data.user.email
  const heading = NAV_ITEMS.find((item) => item.section === section)?.label ?? "Your account"
  const avatar =
    data.user.picture === null
      ? `<div class="avatar avatar--fallback" aria-hidden="true">${escapeHtml(initialsOf(displayName))}</div>`
      : `<img class="avatar" src="${escapeHtml(data.user.picture)}" alt="" referrerpolicy="no-referrer">`

  const tabs = NAV_ITEMS.filter((item) => item.section !== "admin" || data.isAdmin).map((item) => ({
    label: item.label,
    href: `/?section=${item.section}`,
    active: item.section === section,
  }))

  const barRight = `<div class="shell-user">${avatar}<span class="shell-user__name">${escapeHtml(displayName)}</span></div>
      <form method="post" action="/logout">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Sign out</button></form>`

  const notices: Readonly<Record<string, string>> = {
    profile_updated: "Profile saved.",
    password_changed: "Password changed.",
    password_invalid: "Check your current password and make sure the new passwords match.",
    verification_sent: "Verification email sent.",
    email_verified: "Your email is already verified.",
    email_unavailable: "Email delivery is temporarily unavailable.",
    email_change_sent: "Check the new address to confirm your email change.",
    email_change_invalid: "Check the new email and your current password, then try again.",
    passkey_added: "Passkey added.",
    passkey_renamed: "Passkey renamed.",
    passkey_deleted: "Passkey deleted.",
    identity_unlinked: "Connected account removed.",
    identity_linked: "Connected account added.",
    identity_conflict: "That provider account is already connected elsewhere.",
    device_revoked: "Device access revoked.",
    use_connect: "Use the Connect action while signed in.",
    last_login_method: "Add another sign-in method before removing this one.",
    delete_invalid: "Account deletion confirmation did not match.",
    last_active_admin: "Assign another active administrator before deleting this account.",
    invalid: "The request could not be verified.",
    not_found: "That item no longer exists.",
  }
  const notice = data.notice === undefined ? undefined : notices[data.notice]
  const successNotices = new Set([
    "profile_updated",
    "password_changed",
    "verification_sent",
    "email_verified",
    "email_change_sent",
    "passkey_added",
    "passkey_renamed",
    "passkey_deleted",
    "identity_unlinked",
    "identity_linked",
    "device_revoked",
  ])
  const noticeIsSuccess = data.notice !== undefined && successNotices.has(data.notice)
  const noticeHtml =
    notice === undefined
      ? ""
      : `<div class="dash-notice${noticeIsSuccess ? "" : " dash-notice--error"}" role="${noticeIsSuccess ? "status" : "alert"}">${escapeHtml(notice)}</div>`

  return appShell({
    title: "Your account — KeyForge",
    heading,
    barRight,
    tabs,
    content: `${noticeHtml}${renderSection(data, section)}`,
    extraStyles: `.settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin-top:1.2rem}.setting-card{display:flex;flex-direction:column;align-items:flex-start;gap:.8rem;padding:1rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}.setting-card h3{margin:0;font-size:.92rem}.setting-card p{margin:.2rem 0 0;color:var(--ink-2);font-size:.82rem}.setting-card .field{width:100%;margin:0}.setting-card--danger{border-color:var(--danger-line)}.credential-actions,.credential-rename{display:flex;align-items:center;gap:.5rem}.credential-rename .input{width:10rem;padding:.42rem .6rem;font-size:.82rem}.btn--auto{width:auto}.inline-status{margin:0;color:var(--ink-2);font-size:.84rem}.dash-notice{padding:.8rem 1rem;color:var(--ok);background:var(--ok-soft);border:1px solid rgba(121,211,165,.25);border-radius:var(--r-field)}.dash-notice--error{color:var(--danger);background:var(--danger-soft);border-color:var(--danger-line)}@media(max-width:720px){.settings-grid{grid-template-columns:1fr}.credential-actions,.credential-rename{width:100%;flex-wrap:wrap}.credential-rename .input{width:auto;flex:1}}`,
  })
}
