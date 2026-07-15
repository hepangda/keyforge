import type { PasswordCredentialSummary } from "../auth/password"
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
  readonly passwords: readonly PasswordCredentialSummary[]
  readonly passkeys: readonly DashboardPasskey[]
  readonly apps: readonly DashboardApp[]
  readonly devices: readonly DashboardDevice[]
  readonly passwordMinimum: number
  readonly notice?: string
}

export const DASHBOARD_SECTIONS = ["profile", "login-methods", "sessions", "apps", "admin"] as const
export type DashboardSection = (typeof DASHBOARD_SECTIONS)[number]

const NAV_ITEMS: readonly { readonly section: DashboardSection; readonly label: string }[] = [
  { section: "profile", label: "Profile" },
  { section: "login-methods", label: "Login methods" },
  { section: "sessions", label: "Active sessions" },
  { section: "apps", label: "Authorized apps" },
  { section: "admin", label: "Administration" },
]

const AUTH_METHOD_LABELS: Record<AuthMethod, string> = {
  password: "Password",
  magic_link: "Magic link",
  passkey: "Passkey",
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
  const first = parts[0] ?? ""
  const second = parts[1] ?? ""
  return (second ? (first[0] ?? "") + (second[0] ?? "") : first.slice(0, 2) || "?").toUpperCase()
}

function csrfField(token: string): string {
  return `<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">`
}

function renderProfile(data: DashboardData): string {
  const { user, groups } = data
  const displayName = user.name ?? user.alias
  const avatar =
    user.picture === null
      ? `<div class="avatar avatar--fallback" aria-hidden="true">${escapeHtml(initialsOf(displayName))}</div>`
      : `<img class="avatar" src="${escapeHtml(user.picture)}" alt="" referrerpolicy="no-referrer">`
  const emailBadge = user.emailVerified
    ? '<span class="badge badge--ok"><span class="badge__dot"></span>Verified</span>'
    : '<span class="badge badge--warn"><span class="badge__dot"></span>Unverified</span>'
  const groupList = groups.length === 0 ? "—" : groups.map(escapeHtml).join(", ")
  const hasPassword = data.passwords.length > 0
  const verifyEmail = user.emailVerified
    ? ""
    : `<form method="post" action="/account/email/verify">${csrfField(data.csrfToken)}<button class="btn btn--ghost btn--sm" type="submit">Send verification email</button></form>`
  const emailAuthorization = hasPassword
    ? '<label class="field"><span class="field__label">Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>'
    : '<div class="callout">A recent sign-in is required because this account has no password.</div>'

  return `<section class="dash-panel" id="profile">
  <div class="dash-panel__head"><div><h2 class="dash-panel__title">Profile</h2><p class="dash-panel__desc">Your account identity and information shared with approved applications.</p></div></div>
  <div class="dash-panel__body">
    <div class="identity">${avatar}<div class="identity__body"><div class="identity__name">${escapeHtml(displayName)}</div><div class="identity__sub">@${escapeHtml(user.alias)} · ${escapeHtml(user.email)}</div></div></div>
    <div class="meta">
      <div class="meta__row"><span class="meta__key">Username</span><span class="meta__val mono">${escapeHtml(user.alias)}</span></div>
      <div class="meta__row"><span class="meta__key">Email</span><span class="meta__val">${escapeHtml(user.email)}</span></div>
      <div class="meta__row"><span class="meta__key">Verification</span><span class="meta__val">${emailBadge}</span></div>
      <div class="meta__row"><span class="meta__key">Groups</span><span class="meta__val">${groupList}</span></div>
      <div class="meta__row"><span class="meta__key">Member since</span><span class="meta__val mono">${escapeHtml(formatDate(user.createdAt))}</span></div>
    </div>
    <div class="settings-grid">
      <form method="post" action="/account/profile" class="setting-card">
        ${csrfField(data.csrfToken)}
        <div><h3>Public profile</h3><p>Your username may contain only English letters and numbers.</p></div>
        <label class="field"><span class="field__label">Username</span><input class="input" name="alias" pattern="[A-Za-z0-9]+" maxlength="64" value="${escapeHtml(user.alias)}" autocomplete="username" required></label>
        <label class="field"><span class="field__label">Display name</span><input class="input" name="name" maxlength="120" value="${escapeHtml(user.name ?? "")}" autocomplete="name"></label>
        <button class="btn btn--ghost btn--sm" type="submit">Save profile</button>
      </form>
      <div class="setting-card"><div><h3>Email verification</h3><p>${user.emailVerified ? "This address has been verified." : "Verify this address before applications treat it as confirmed."}</p></div>${verifyEmail}</div>
      <form method="post" action="/account/email/change" class="setting-card">
        ${csrfField(data.csrfToken)}
        <div><h3>Change email</h3><p>We confirm the new address before changing your sign-in email.</p></div>
        <label class="field"><span class="field__label">New email</span><input class="input" type="email" name="new_email" autocomplete="email" maxlength="254" required></label>
        ${emailAuthorization}
        <button class="btn btn--ghost btn--sm" type="submit">Send confirmation</button>
      </form>
      <form method="post" action="/account/delete" class="setting-card setting-card--danger">
        ${csrfField(data.csrfToken)}
        <div><h3>Delete account</h3><p>Permanently removes sessions, login methods, and application grants.</p></div>
        <label class="field"><span class="field__label">Type ${escapeHtml(user.email)} to confirm</span><input class="input" name="confirmation" autocomplete="off" required></label>
        ${hasPassword ? '<label class="field"><span class="field__label">Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>' : ""}
        <button class="btn btn--danger btn--sm" type="submit">Delete account</button>
      </form>
    </div>
  </div>
</section>`
}

function credentialActions(
  data: DashboardData,
  kind: "passwords" | "passkeys",
  id: string,
  name: string | null,
): string {
  const label = kind === "passwords" ? "Password name" : "Passkey name"
  return `<div class="credential-actions">
    <form method="post" action="/account/${kind}/${escapeHtml(id)}/rename" class="credential-rename">
      ${csrfField(data.csrfToken)}
      <input class="input" name="name" maxlength="80" aria-label="${label}" placeholder="${label}" value="${escapeHtml(name ?? "")}">
      <button class="btn btn--ghost btn--sm" type="submit">Rename</button>
    </form>
    <form method="post" action="/account/${kind}/${escapeHtml(id)}/delete">${csrfField(data.csrfToken)}<button class="btn btn--ghost btn--sm" type="submit">Delete</button></form>
  </div>`
}

function renderLoginMethods(data: DashboardData): string {
  const passwordRows = data.passwords.map(
    (password) => `<li class="dash-list__item">
      <div class="method-mark" aria-hidden="true">${icons.key}</div>
      <div class="dash-item__main"><div class="dash-item__title">${escapeHtml(password.name ?? "Password")} <span class="method-kind">Password</span></div><div class="dash-item__meta">Added <span class="mono">${formatDate(password.createdAt)}</span>${password.lastUsedAt === null ? "" : ` · Last used <span class="mono">${formatDate(password.lastUsedAt)}</span>`}${data.isAdmin && !password.adminEligible ? " · Not available for administrator sign-in" : ""}</div></div>
      ${credentialActions(data, "passwords", password.id, password.name)}
    </li>`,
  )
  const passkeyRows = data.passkeys.map(
    (passkey) => `<li class="dash-list__item">
      <div class="method-mark method-mark--passkey" aria-hidden="true">${icons.key}</div>
      <div class="dash-item__main"><div class="dash-item__title">${escapeHtml(passkey.name ?? "Passkey")} <span class="method-kind">Passkey</span></div><div class="dash-item__meta">Added <span class="mono">${formatDate(passkey.createdAt)}</span>${passkey.lastUsedAt === null ? "" : ` · Last used <span class="mono">${formatDate(passkey.lastUsedAt)}</span>`}</div></div>
      ${credentialActions(data, "passkeys", passkey.id, passkey.name)}
    </li>`,
  )
  const rows = [...passwordRows, ...passkeyRows]
  const currentPassword =
    data.passwords.length === 0
      ? '<div class="callout">You are adding the first password to this account. A recent sign-in is required.</div>'
      : '<label class="field"><span class="field__label">Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>'
  return `<section class="dash-panel" id="login-methods">
    <div class="dash-panel__head"><div><h2 class="dash-panel__title">Login methods</h2><p class="dash-panel__desc">Passwords and passkeys are independent ways to access this account. Add more than one for recovery.</p></div><button class="btn btn--primary btn--sm btn--auto" type="button" data-passkey-register data-csrf="${escapeHtml(data.csrfToken)}">Add passkey</button></div>
    <ul class="dash-list">${rows.length === 0 ? '<li class="dash-list__item--empty">No reusable login methods yet. Add a password or passkey.</li>' : rows.join("\n")}</ul>
    <div class="dash-panel__foot login-method-add">
      <form method="post" action="/account/passwords" class="method-form">
        ${csrfField(data.csrfToken)}
        <div class="method-form__intro"><h3>Add a password</h3><p>Use ${data.passwordMinimum}–128 characters${data.isAdmin ? "; administrator passwords require at least 12" : ""}.</p></div>
        <label class="field"><span class="field__label">Name</span><input class="input" name="name" maxlength="80" placeholder="e.g. Password manager"></label>
        ${currentPassword}
        <label class="field"><span class="field__label">New password</span><input class="input" type="password" name="password" minlength="${data.passwordMinimum}" maxlength="128" autocomplete="new-password" required></label>
        <label class="field"><span class="field__label">Confirm password</span><input class="input" type="password" name="password_confirm" minlength="${data.passwordMinimum}" maxlength="128" autocomplete="new-password" required></label>
        <button class="btn btn--ghost btn--sm btn--auto" type="submit">Add password</button>
      </form>
      <p class="inline-status" data-passkey-status role="status" hidden></p>
    </div>
    <script src="/assets/account.js" defer></script>
  </section>`
}

function renderSessions(data: DashboardData): string {
  const rows = data.sessions
    .map((session) => {
      const current = session.current ? ' <span class="dash-item__current">This device</span>' : ""
      const action = session.current
        ? ""
        : `<form method="post" action="/account/sessions/${escapeHtml(session.id)}/revoke">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Sign out</button></form>`
      return `<li class="dash-list__item"><div class="dash-item__main"><div class="dash-item__title">${escapeHtml(AUTH_METHOD_LABELS[session.authMethod])}${current}</div><div class="dash-item__meta">Started <span class="mono">${formatDate(session.createdAt)}</span> · Last active <span class="mono">${formatDate(session.lastSeenAt)}</span> · Expires <span class="mono">${formatDate(session.expiresAt)}</span></div></div><div class="dash-item__actions">${action}</div></li>`
    })
    .join("\n")
  const others = data.sessions.filter((session) => !session.current).length
  return `<section class="dash-panel" id="sessions"><div class="dash-panel__head"><div><h2 class="dash-panel__title">Active sessions</h2><p class="dash-panel__desc">Devices and browsers currently signed in to your account.</p></div></div><ul class="dash-list">${rows}</ul>${others === 0 ? "" : `<div class="dash-panel__foot dash-panel__foot--end"><form method="post" action="/account/sessions/revoke-others">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Sign out all other sessions</button></form></div>`}</section>`
}

function renderApps(data: DashboardData): string {
  const rows = data.apps.map(
    (app) =>
      `<li class="dash-list__item"><div class="dash-item__main"><div class="dash-item__title">${escapeHtml(app.name)}</div><div class="dash-item__meta"><span class="dash-item__icon">${icons.key}</span><span class="mono">${app.scopes.map(escapeHtml).join(", ")}</span></div><div class="dash-item__meta">Resources: <span class="mono">${app.resources.map(escapeHtml).join(", ")}</span></div></div><div class="dash-item__actions"><form method="post" action="/account/apps/${encodeURIComponent(app.clientId)}/revoke">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Revoke all access</button></form></div></li>`,
  )
  const devices = data.devices.map(
    (device) =>
      `<li class="dash-list__item"><div class="dash-item__main"><div class="dash-item__title">${escapeHtml(device.clientName)}</div><div class="dash-item__meta"><span class="mono">${escapeHtml(device.resource)}</span> · Last used ${formatDate(device.lastRotatedAt)} · Expires ${formatDate(device.expiresAt)}</div></div><div class="dash-item__actions"><form method="post" action="/account/devices/${encodeURIComponent(device.familyId)}/revoke">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Revoke device</button></form></div></li>`,
  )
  return `<section class="dash-panel" id="apps"><div class="dash-panel__head"><div><h2 class="dash-panel__title">Authorized apps</h2><p class="dash-panel__desc">Applications you have granted access to your account.</p></div></div><ul class="dash-list">${rows.length === 0 ? '<li class="dash-list__item--empty">No applications currently have access.</li>' : rows.join("\n")}</ul></section><section class="dash-panel" id="authorized-devices"><div class="dash-panel__head"><div><h2 class="dash-panel__title">Authorized CLI and devices</h2><p class="dash-panel__desc">Refresh access issued independently to a device.</p></div></div><ul class="dash-list">${devices.length === 0 ? '<li class="dash-list__item--empty">No independently authorized device sessions.</li>' : devices.join("\n")}</ul></section>`
}

function renderAdmin(isAdmin: boolean): string {
  if (!isAdmin) return ""
  return `<section class="dash-panel" id="admin"><div class="dash-panel__head"><div><h2 class="dash-panel__title">Administration</h2><p class="dash-panel__desc">Configure applications, users, resources, devices, and audit activity.</p></div><a href="/console" class="btn btn--primary btn--sm">Open admin console</a></div></section>`
}

function renderSection(data: DashboardData, section: DashboardSection): string {
  switch (section) {
    case "profile":
      return renderProfile(data)
    case "login-methods":
      return renderLoginMethods(data)
    case "sessions":
      return renderSessions(data)
    case "apps":
      return renderApps(data)
    case "admin":
      return renderAdmin(data.isAdmin)
  }
}

const NOTICES: Readonly<Record<string, string>> = {
  profile_updated: "Profile saved.",
  alias_invalid: "Choose an available username using only English letters and numbers.",
  password_added: "Password added.",
  password_renamed: "Password renamed.",
  password_deleted: "Password deleted.",
  password_invalid: "Check the current password, new password policy, and confirmation.",
  verification_sent: "Verification email sent.",
  email_verified: "Your email is already verified.",
  email_unavailable: "Email delivery is temporarily unavailable.",
  email_change_sent: "Check the new address to confirm your email change.",
  email_change_invalid: "Check the new email and current password, then try again.",
  passkey_added: "Passkey added.",
  passkey_renamed: "Passkey renamed.",
  passkey_deleted: "Passkey deleted.",
  device_revoked: "Device access revoked.",
  last_login_method: "Add another password or passkey before removing this one.",
  delete_invalid: "Account deletion confirmation did not match.",
  last_active_admin: "Assign another active administrator before deleting this account.",
  invalid: "The request could not be verified.",
  not_found: "That item no longer exists.",
}

const SUCCESS_NOTICES = new Set([
  "profile_updated",
  "password_added",
  "password_renamed",
  "password_deleted",
  "verification_sent",
  "email_verified",
  "email_change_sent",
  "passkey_added",
  "passkey_renamed",
  "passkey_deleted",
  "device_revoked",
])

export function renderDashboard(data: DashboardData, section: DashboardSection): string {
  const displayName = data.user.name ?? data.user.alias
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
  const barRight = `<div class="shell-user">${avatar}<span class="shell-user__name">${escapeHtml(displayName)}</span></div><form method="post" action="/logout">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">Sign out</button></form>`
  const notice = data.notice === undefined ? undefined : NOTICES[data.notice]
  const success = data.notice !== undefined && SUCCESS_NOTICES.has(data.notice)
  const noticeHtml =
    notice === undefined
      ? ""
      : `<div class="dash-notice${success ? "" : " dash-notice--error"}" role="${success ? "status" : "alert"}">${escapeHtml(notice)}</div>`

  return appShell({
    title: "Your account — KeyForge",
    heading,
    barRight,
    tabs,
    content: `${noticeHtml}${renderSection(data, section)}`,
    extraStyles: `.settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin-top:1.2rem}.setting-card{display:flex;flex-direction:column;align-items:flex-start;gap:.8rem;padding:1rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}.setting-card h3,.method-form h3{margin:0;font-size:.92rem}.setting-card p,.method-form p{margin:.2rem 0 0;color:var(--ink-2);font-size:.82rem}.setting-card .field,.method-form .field{width:100%;margin:0}.setting-card--danger{border-color:var(--danger-line)}.credential-actions,.credential-rename{display:flex;align-items:center;gap:.5rem}.credential-actions{flex:none}.credential-rename .input{width:10rem;padding:.42rem .6rem;font-size:.82rem}.method-mark{display:grid;place-items:center;flex:none;width:36px;height:36px;border-radius:10px;color:var(--brass);background:var(--brass-soft);border:1px solid var(--brass-line)}.method-mark--passkey{color:var(--ok);background:var(--ok-soft);border-color:transparent}.method-kind{font-size:.65rem;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-3);border:1px solid var(--line-2);border-radius:var(--r-pill);padding:.08rem .38rem}.login-method-add{padding:1.35rem 1.6rem}.method-form{display:grid;grid-template-columns:1.2fr repeat(3,minmax(150px,1fr)) auto;gap:.8rem;align-items:end}.method-form__intro{align-self:center}.btn--auto{width:auto}.inline-status{margin:.8rem 0 0;color:var(--ink-2);font-size:.84rem}.dash-notice{padding:.8rem 1rem;color:var(--ok);background:var(--ok-soft);border:1px solid rgba(121,211,165,.25);border-radius:var(--r-field)}.dash-notice--error{color:var(--danger);background:var(--danger-soft);border-color:var(--danger-line)}@media(max-width:920px){.method-form{grid-template-columns:1fr 1fr}.method-form__intro{grid-column:1/-1}}@media(max-width:720px){.settings-grid,.method-form{grid-template-columns:1fr}.credential-actions,.credential-rename{width:100%;flex-wrap:wrap}.credential-rename .input{width:auto;flex:1}.dash-list__item .method-mark{display:none}}`,
  })
}
