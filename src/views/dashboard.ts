import type { PasswordCredentialSummary } from "../auth/password"
import type { I18n } from "../i18n"
import { AVATAR_TARGET_DIMENSION, MAX_AVATAR_BYTES } from "../media/avatar"
import type { AuthMethod, User } from "../types/domain"
import { appShell, avatarMarkup, escapeHtml, icons } from "./layout"

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
  readonly i18n: I18n
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

export const DASHBOARD_FLOWS = [
  "edit-profile",
  "change-email",
  "delete-account",
  "add-password",
  "add-passkey",
  "manage-password",
  "manage-passkey",
  "remove-password",
  "remove-passkey",
  "revoke-app",
  "revoke-device",
  "revoke-other-sessions",
] as const
export type DashboardFlow = (typeof DASHBOARD_FLOWS)[number]

export type DashboardView = {
  readonly flow: DashboardFlow | null
  readonly targetId: string | null
}

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

function csrfField(token: string): string {
  return `<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">`
}

function dashboardHref(
  section: DashboardSection,
  options: {
    readonly flow?: DashboardFlow
    readonly targetId?: string
  } = {},
): string {
  const query = new URLSearchParams({ section })
  if (options.flow !== undefined) query.set("flow", options.flow)
  if (options.targetId !== undefined) query.set("target", options.targetId)
  return `/?${query.toString()}`
}

function flowPanel(
  i18n: I18n,
  title: string,
  description: string,
  backLabel: string,
  backHref: string,
  body: string,
): string {
  return `<div class="flow-page"><a class="btn btn--ghost btn--sm btn--auto flow-back back-link" href="${escapeHtml(backHref)}">${escapeHtml(i18n.t(backLabel))}</a><section class="dash-panel flow-panel">
    <div class="dash-panel__head flow-panel__head"><div class="flow-panel__intro"><h2 class="dash-panel__title">${escapeHtml(i18n.t(title))}</h2><p class="dash-panel__desc">${escapeHtml(i18n.t(description))}</p></div></div>
    <div class="dash-panel__body flow-panel__body">${body}</div>
  </section></div>`
}

function renderProfileOverview(data: DashboardData): string {
  const { i18n, user, groups } = data
  const displayName = user.name ?? user.alias
  const avatar = avatarMarkup(user)
  const emailBadge = user.emailVerified
    ? `<span class="badge badge--ok"><span class="badge__dot"></span>${escapeHtml(i18n.t("Verified"))}</span>`
    : `<span class="badge badge--warn"><span class="badge__dot"></span>${escapeHtml(i18n.t("Unverified"))}</span>`
  const groupList =
    groups.length === 0
      ? "—"
      : groups
          .map(
            (group) =>
              `<span class="group-chip" title="${escapeHtml(group)}">${escapeHtml(group)}</span>`,
          )
          .join("")
  const verifyEmail = user.emailVerified
    ? ""
    : `<form method="post" action="/account/email/verify">${csrfField(data.csrfToken)}<button class="btn btn--ghost btn--sm btn--auto" type="submit">${escapeHtml(i18n.t("Send verification email"))}</button></form>`

  return `<section class="dash-panel" id="profile">
    <div class="dash-panel__head"><div><h2 class="dash-panel__title">${escapeHtml(i18n.t("Profile"))}</h2><p class="dash-panel__desc">${escapeHtml(i18n.t("Review your identity, then choose one account detail to manage."))}</p></div></div>
    <div class="dash-panel__body">
      <div class="identity profile-summary">${avatar}<div class="identity__body"><div class="identity__name">${escapeHtml(displayName)}</div><div class="identity__sub">@${escapeHtml(user.alias)}</div></div><a class="btn btn--ghost btn--sm btn--auto" href="${dashboardHref("profile", { flow: "edit-profile" })}" aria-label="${escapeHtml(i18n.t("Edit profile"))}">${escapeHtml(i18n.t("Edit"))}</a></div>
      <div class="meta">
        <div class="meta__row meta__row--identity"><span class="meta__key">${escapeHtml(i18n.t("User ID"))}</span><span class="meta__val mono">${escapeHtml(user.id)}</span></div>
        <div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Email"))}</span><span class="meta__val meta__val--email"><span class="meta__email">${escapeHtml(user.email)}</span>${emailBadge}</span></div>
        <div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Groups"))}</span><span class="meta__val group-list">${groupList}</span></div>
        <div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Member since"))}</span><span class="meta__val mono">${escapeHtml(i18n.formatDate(user.createdAt))}</span></div>
      </div>
      <div class="action-list" aria-label="${escapeHtml(i18n.t("Account actions"))}">
        <div class="action-row"><div><h3>${escapeHtml(i18n.t("Email address"))}</h3><p>${escapeHtml(i18n.t("Change your sign-in email or verify the current address."))}</p></div><div class="action-row__actions">${verifyEmail}<a class="btn btn--ghost btn--sm btn--auto" href="${dashboardHref("profile", { flow: "change-email" })}">${escapeHtml(i18n.t("Change"))}</a></div></div>
        <div class="action-row action-row--danger"><div><h3>${escapeHtml(i18n.t("Delete account"))}</h3><p>${escapeHtml(i18n.t("Permanently removes sessions, login methods, and application grants."))}</p></div><a class="btn btn--danger btn--sm btn--auto" href="${dashboardHref("profile", { flow: "delete-account" })}">${escapeHtml(i18n.t("Review"))}</a></div>
      </div>
    </div>
  </section>`
}

function renderProfile(data: DashboardData, view: DashboardView): string {
  const { i18n, user } = data
  const backHref = dashboardHref("profile")
  if (view.flow === "edit-profile") {
    const removePhoto = `<form method="post" action="/account/avatar/delete" data-avatar-remove${user.avatarKey === null ? " hidden" : ""}>${csrfField(data.csrfToken)}<button class="btn btn--ghost btn--sm btn--auto" type="submit">${escapeHtml(i18n.t("Remove photo"))}</button></form>`
    // Uploads run in the page so the user sees a preview, progress, and a
    // specific error instead of a full-page navigation. Without JavaScript the
    // same form posts normally and the server redirects with a notice.
    const avatarMessages = [
      ["cropHint", "Drag the square to choose the part of the photo to use."],
      ["preparing", "Preparing your photo…"],
      ["uploading", "Uploading…"],
      ["saved", "Profile photo updated."],
      ["tooLarge", "That photo is too large even after resizing. Choose a smaller image."],
      ["unsupported", "Choose a PNG, JPEG, WebP, or GIF image."],
      ["missing", "Choose an image file to upload."],
      ["rateLimited", "Too many photo uploads. Try again later."],
      ["invalid", "The request could not be verified."],
      ["failed", "The photo could not be uploaded. Try again."],
    ]
      .map(
        ([key, message]) =>
          `data-message-${key as string}="${escapeHtml(i18n.t(message as string))}"`,
      )
      .join(" ")
    const body = `<div class="readonly-field"><span>${escapeHtml(i18n.t("Username"))}</span><strong class="mono">${escapeHtml(user.alias)}</strong><small>${escapeHtml(i18n.t("Only an administrator can change your username."))}</small></div>
      <div class="profile-edit-grid">
        <form method="post" action="/account/avatar" enctype="multipart/form-data" class="flow-form flow-form--single avatar-form" data-avatar-form data-max-bytes="${MAX_AVATAR_BYTES}" data-dimension="${AVATAR_TARGET_DIMENSION}" ${avatarMessages}>
          ${csrfField(data.csrfToken)}
          <div class="avatar-editor">${avatarMarkup(user, "avatar--lg", "data-avatar-preview")}<div class="avatar-editor__body"><label class="field"><span class="field__label">${escapeHtml(i18n.t("Profile photo"))}</span><input class="input" type="file" name="avatar" accept="image/png,image/jpeg,image/webp,image/gif" required></label><small>${escapeHtml(i18n.t("PNG, JPEG, WebP, or GIF. Choose the part of the photo to use after selecting it."))}</small></div></div>
          <div class="avatar-crop" data-avatar-cropper hidden>
            <canvas class="avatar-crop__canvas" data-avatar-canvas width="320" height="320" tabindex="0" role="application" aria-label="${escapeHtml(i18n.t("Drag the square to choose the part of the photo to use."))}"></canvas>
            <p class="avatar-crop__hint">${escapeHtml(i18n.t("Drag inside the square to move it, or drag a corner to resize."))}</p>
          </div>
          <p class="inline-status" data-avatar-status role="status" hidden></p>
          <div class="action-row__actions form-actions"><button class="btn btn--primary btn--auto" type="submit" data-avatar-submit>${escapeHtml(i18n.t("Save photo"))}</button><button class="btn btn--ghost btn--sm btn--auto" type="button" data-avatar-reset>${escapeHtml(i18n.t("Reset selection"))}</button><button class="btn btn--ghost btn--sm btn--auto" type="button" data-avatar-cancel>${escapeHtml(i18n.t("Cancel"))}</button>${removePhoto}</div>
        </form>
        <form method="post" action="/account/profile" class="flow-form flow-form--single profile-name-form">
          ${csrfField(data.csrfToken)}
          <label class="field"><span class="field__label">${escapeHtml(i18n.t("Display name"))}</span><input class="input" name="name" maxlength="120" value="${escapeHtml(user.name ?? "")}" autocomplete="name"></label>
          <div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save profile"))}</button></div>
        </form>
      </div>
      <script src="/assets/avatar.js" defer></script>`
    return flowPanel(
      i18n,
      "Edit profile",
      "Your username is managed by an administrator; you can update the name shown to applications.",
      "Back to profile",
      backHref,
      body,
    )
  }
  if (view.flow === "change-email") {
    const hasPassword = data.passwords.length > 0
    const authorization = hasPassword
      ? `<label class="field"><span class="field__label">${escapeHtml(i18n.t("Current password"))}</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>`
      : `<div class="callout">${escapeHtml(i18n.t("Because this account has no password, a sign-in within the last 10 minutes is required to make changes."))}</div>`
    const body = `<div class="flow-steps flow-steps--email"><div class="flow-step flow-step--active"><span>1</span><div><b>${escapeHtml(i18n.t("Request change"))}</b><small>${escapeHtml(i18n.t("Enter and authorize the new address."))}</small></div></div><div class="flow-step"><span>2</span><div><b>${escapeHtml(i18n.t("Confirm email"))}</b><small>${escapeHtml(i18n.t("Open the single-use link we send."))}</small></div></div></div>
      <form method="post" action="/account/email/change" class="flow-form">
        ${csrfField(data.csrfToken)}
        <label class="field"><span class="field__label">${escapeHtml(i18n.t("New email"))}</span><input class="input" type="email" name="new_email" autocomplete="email" maxlength="254" required></label>
        ${authorization}
        <div class="form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Send confirmation"))}</button></div>
      </form>`
    return flowPanel(
      i18n,
      "Change email",
      "Your sign-in email changes only after the new address is confirmed.",
      "Back to profile",
      backHref,
      body,
    )
  }
  if (view.flow === "delete-account") {
    const hasPassword = data.passwords.length > 0
    const password = hasPassword
      ? `<label class="field"><span class="field__label">${escapeHtml(i18n.t("Current password"))}</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>`
      : ""
    const body = `<div class="alert" role="alert">${icons.alert}<div><strong>${escapeHtml(i18n.t("This cannot be undone."))}</strong><br>${escapeHtml(i18n.t("Every session, login method, and application grant will be removed."))}</div></div>
      <form method="post" action="/account/delete" class="flow-form">
        ${csrfField(data.csrfToken)}
        <label class="field"><span class="field__label">${escapeHtml(i18n.t("Type {value} to confirm", { value: user.email }))}</span><input class="input" name="confirmation" autocomplete="off" required></label>
        ${password}
        <div class="form-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Delete account"))}</button></div>
      </form>`
    return flowPanel(
      i18n,
      "Delete account",
      "Review the impact and confirm only if you want to permanently remove this account.",
      "Back to profile",
      backHref,
      body,
    )
  }
  return renderProfileOverview(data)
}

function renderLoginMethodsOverview(data: DashboardData): string {
  const { i18n } = data
  const passwordRows = data.passwords.map(
    (password) => `<li class="dash-list__item">
      <div class="method-mark" aria-hidden="true">${icons.key}</div>
      <div class="dash-item__main"><div class="dash-item__title">${escapeHtml(password.name ?? i18n.t("Password"))} <span class="method-kind">${escapeHtml(i18n.t("Password"))}</span></div><div class="dash-item__meta">${escapeHtml(i18n.t("Added"))} <span class="mono">${i18n.formatDate(password.createdAt)}</span>${password.lastUsedAt === null ? "" : ` · ${escapeHtml(i18n.t("Last used"))} <span class="mono">${i18n.formatDate(password.lastUsedAt)}</span>`}</div>${data.isAdmin && !password.adminEligible ? `<div class="method-warning">${escapeHtml(i18n.t("This password does not meet the administrator minimum. Use a passkey or another eligible password for admin actions."))}</div>` : ""}</div>
      <a class="btn btn--ghost btn--sm btn--auto" href="${dashboardHref("login-methods", { flow: "manage-password", targetId: password.id })}">${escapeHtml(i18n.t("Manage"))}</a>
    </li>`,
  )
  const passkeyRows = data.passkeys.map(
    (passkey) => `<li class="dash-list__item">
      <div class="method-mark method-mark--passkey" aria-hidden="true">${icons.key}</div>
      <div class="dash-item__main"><div class="dash-item__title">${escapeHtml(passkey.name ?? i18n.t("Passkey"))} <span class="method-kind">${escapeHtml(i18n.t("Passkey"))}</span></div><div class="dash-item__meta">${escapeHtml(i18n.t("Added"))} <span class="mono">${i18n.formatDate(passkey.createdAt)}</span>${passkey.lastUsedAt === null ? "" : ` · ${escapeHtml(i18n.t("Last used"))} <span class="mono">${i18n.formatDate(passkey.lastUsedAt)}</span>`}</div></div>
      <a class="btn btn--ghost btn--sm btn--auto" href="${dashboardHref("login-methods", { flow: "manage-passkey", targetId: passkey.id })}">${escapeHtml(i18n.t("Manage"))}</a>
    </li>`,
  )
  const rows = [...passwordRows, ...passkeyRows]
  return `<section class="dash-panel" id="login-methods">
    <div class="dash-panel__head"><div><h2 class="dash-panel__title">${escapeHtml(i18n.t("Login methods"))}</h2><p class="dash-panel__desc">${escapeHtml(i18n.t("Choose one method to manage, or add a recovery method."))}</p></div><div class="action-row__actions"><a class="btn btn--primary btn--sm btn--auto" href="${dashboardHref("login-methods", { flow: "add-passkey" })}">${escapeHtml(i18n.t("Add passkey"))}</a><a class="btn btn--ghost btn--sm btn--auto" href="${dashboardHref("login-methods", { flow: "add-password" })}">${escapeHtml(i18n.t("Add password"))}</a></div></div>
    <ul class="dash-list">${rows.length === 0 ? `<li class="dash-list__item--empty">${escapeHtml(i18n.t("No reusable login methods yet. Add a password or passkey."))}</li>` : rows.join("\n")}</ul>
  </section>`
}

function renderAddPassword(data: DashboardData): string {
  const { i18n } = data
  const content = `<form method="post" action="/account/passwords" class="flow-form">
      ${csrfField(data.csrfToken)}
      <label class="field field--wide"><span class="field__label">${escapeHtml(i18n.t("Name"))}</span><input class="input" name="name" maxlength="80" placeholder="${escapeHtml(i18n.t("e.g. Password manager"))}"></label>
      <label class="field"><span class="field__label">${escapeHtml(i18n.t("New password"))}</span><input class="input" type="password" name="password" minlength="${data.passwordMinimum}" maxlength="128" autocomplete="new-password" required></label>
      <label class="field"><span class="field__label">${escapeHtml(i18n.t("Confirm password"))}</span><input class="input" type="password" name="password_confirm" minlength="${data.passwordMinimum}" maxlength="128" autocomplete="new-password" required></label>
      <p class="form-hint form-hint--wide">${escapeHtml(i18n.t(data.isAdmin ? "Use {minimum}–128 characters; administrator passwords require at least 12." : "Use {minimum}–128 characters.", { minimum: data.passwordMinimum }))}</p>

      <div class="flow-actions form-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Add password"))}</button></div>
    </form>`
  return flowPanel(
    i18n,
    "Add a password",
    "Add a separate password for recovery or another password manager.",
    "Back to login methods",
    dashboardHref("login-methods"),
    content,
  )
}

function passkeyButton(data: DashboardData): string {
  const { i18n } = data
  return `<div class="passkey-setup"><div class="passkey-setup__intro"><div class="method-mark method-mark--passkey" aria-hidden="true">${icons.key}</div><div><h3>${escapeHtml(i18n.t("Create your passkey"))}</h3><p>${escapeHtml(i18n.t("Your browser will ask where to save the new passkey."))}</p></div></div><div class="flow-actions"><button class="btn btn--primary btn--auto" type="button" data-passkey-register data-csrf="${escapeHtml(data.csrfToken)}" data-return-to="/?section=login-methods&amp;flow=add-passkey" data-waiting-message="${escapeHtml(i18n.t("Follow your browser's passkey prompt…"))}" data-cancelled-message="${escapeHtml(i18n.t("Passkey creation was cancelled."))}" data-error-message="${escapeHtml(i18n.t("Passkey creation could not be completed."))}" data-network-error-message="${escapeHtml(i18n.t("Could not reach the server. Check your connection and try again."))}" data-rate-limited-message="${escapeHtml(i18n.t("Too many attempts. Please wait and try again."))}" hidden>${escapeHtml(i18n.t("Add passkey"))}</button></div><p class="inline-status" data-passkey-status role="status" hidden></p><p class="foot"><a class="link-quiet" href="${dashboardHref("login-methods", { flow: "add-password" })}">${escapeHtml(i18n.t("Add a password instead"))}</a></p></div>`
}

function renderAddPasskey(data: DashboardData): string {
  const { i18n } = data
  return flowPanel(
    i18n,
    "Add a passkey",
    "Use a device, security key, or password manager without typing a password.",
    "Back to login methods",
    dashboardHref("login-methods"),
    `${passkeyButton(data)}<script src="/assets/account.js" defer></script>`,
  )
}

function renderManageCredential(
  data: DashboardData,
  view: DashboardView,
  kind: "password" | "passkey",
): string {
  const { i18n } = data
  const credential =
    kind === "password"
      ? data.passwords.find((item) => item.id === view.targetId)
      : data.passkeys.find((item) => item.id === view.targetId)
  if (credential === undefined) return renderLoginMethodsOverview(data)
  const plural = kind === "password" ? "passwords" : "passkeys"
  const fallbackName = i18n.t(kind === "password" ? "Password" : "Passkey")
  const displayName = credential.name ?? fallbackName
  const removeFlow = kind === "password" ? "remove-password" : "remove-passkey"
  const content = `<div class="credential-summary"><div class="method-mark${kind === "passkey" ? " method-mark--passkey" : ""}" aria-hidden="true">${icons.key}</div><div><strong>${escapeHtml(displayName)}</strong><span>${escapeHtml(fallbackName)} · ${escapeHtml(i18n.t("Added"))} ${escapeHtml(i18n.formatDate(credential.createdAt))}</span></div></div>
    <div class="manage-stack">
      <form method="post" action="/account/${plural}/${escapeHtml(credential.id)}/rename" class="flow-form manage-form">
        ${csrfField(data.csrfToken)}
        <div><h3>${escapeHtml(i18n.t("Rename"))}</h3><p>${escapeHtml(i18n.t("Use a name that helps you recognize where this method is stored."))}</p></div>
        <label class="field"><span class="field__label">${escapeHtml(i18n.t(kind === "password" ? "Password name" : "Passkey name"))}</span><input class="input" name="name" maxlength="80" value="${escapeHtml(credential.name ?? "")}"></label>
        <div class="flow-actions"><button class="btn btn--primary btn--auto" type="submit">${escapeHtml(i18n.t("Save name"))}</button></div>
      </form>
      <div class="manage-form manage-form--danger"><div><h3>${escapeHtml(i18n.t("Remove login method"))}</h3><p>${escapeHtml(i18n.t("Review the impact before removing this login method."))}</p></div><div class="flow-actions"><a class="btn btn--danger btn--auto" href="${escapeHtml(dashboardHref("login-methods", { flow: removeFlow, targetId: credential.id }))}">${escapeHtml(i18n.t("Review"))}</a></div></div>
    </div>`
  return flowPanel(
    i18n,
    kind === "password" ? "Manage password" : "Manage passkey",
    "Use a name that helps you recognize where this method is stored.",
    "Back to login methods",
    dashboardHref("login-methods"),
    content,
  )
}

function renderRemoveCredential(
  data: DashboardData,
  view: DashboardView,
  kind: "password" | "passkey",
): string {
  const { i18n } = data
  const credential =
    kind === "password"
      ? data.passwords.find((item) => item.id === view.targetId)
      : data.passkeys.find((item) => item.id === view.targetId)
  if (credential === undefined) return renderLoginMethodsOverview(data)
  const fallbackName = i18n.t(kind === "password" ? "Password" : "Passkey")
  const displayName = credential.name ?? fallbackName
  const manageFlow = kind === "password" ? "manage-password" : "manage-passkey"
  const plural = kind === "password" ? "passwords" : "passkeys"
  const lastUsed =
    credential.lastUsedAt === null ? i18n.t("Never") : i18n.formatDate(credential.lastUsedAt)
  const content = `<div class="credential-summary"><div class="method-mark${kind === "passkey" ? " method-mark--passkey" : ""}" aria-hidden="true">${icons.key}</div><div><strong>${escapeHtml(displayName)}</strong><span>${escapeHtml(fallbackName)}</span></div></div>
    <div class="meta"><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Name"))}</span><span class="meta__val">${escapeHtml(displayName)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Type"))}</span><span class="meta__val">${escapeHtml(fallbackName)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Last used"))}</span><span class="meta__val mono">${escapeHtml(lastUsed)}</span></div></div>
    <div class="callout">${escapeHtml(i18n.t("You will no longer be able to sign in with this method. Keep at least one password or passkey."))}</div>
    <form method="post" action="/account/${plural}/${escapeHtml(credential.id)}/delete" class="flow-form flow-form--single">${csrfField(data.csrfToken)}<div class="flow-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Remove login method"))}</button><a class="btn btn--ghost btn--auto" href="${escapeHtml(dashboardHref("login-methods", { flow: manageFlow, targetId: credential.id }))}">${escapeHtml(i18n.t("Cancel"))}</a></div></form>`
  return flowPanel(
    i18n,
    "Remove login method",
    "Review the login method and its last use before removing it.",
    "Back to login method",
    dashboardHref("login-methods", { flow: manageFlow, targetId: credential.id }),
    content,
  )
}

function renderLoginMethods(data: DashboardData, view: DashboardView): string {
  switch (view.flow) {
    case "add-password":
      return renderAddPassword(data)
    case "add-passkey":
      return renderAddPasskey(data)
    case "manage-password":
      return renderManageCredential(data, view, "password")
    case "manage-passkey":
      return renderManageCredential(data, view, "passkey")
    case "remove-password":
      return renderRemoveCredential(data, view, "password")
    case "remove-passkey":
      return renderRemoveCredential(data, view, "passkey")
    default:
      return renderLoginMethodsOverview(data)
  }
}

function renderSessions(data: DashboardData, view: DashboardView): string {
  const { i18n } = data
  const rows = data.sessions
    .map((session) => {
      const current = session.current
        ? ` <span class="dash-item__current">${escapeHtml(i18n.t("This device"))}</span>`
        : ""
      const action = session.current
        ? ""
        : `<form method="post" action="/account/sessions/${escapeHtml(session.id)}/revoke">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">${escapeHtml(i18n.t("Sign out"))}</button></form>`
      return `<li class="dash-list__item"><div class="dash-item__main"><div class="dash-item__title">${escapeHtml(i18n.t(AUTH_METHOD_LABELS[session.authMethod]))}${current}</div><div class="dash-item__meta">${escapeHtml(i18n.t("Started"))} <span class="mono">${i18n.formatDate(session.createdAt)}</span> · ${escapeHtml(i18n.t("Last active"))} <span class="mono">${i18n.formatDate(session.lastSeenAt)}</span> · ${escapeHtml(i18n.t("Expires"))} <span class="mono">${i18n.formatDate(session.expiresAt)}</span></div></div><div class="dash-item__actions">${action}</div></li>`
    })
    .join("\n")
  const others = data.sessions.filter((session) => !session.current).length
  if (view.flow === "revoke-other-sessions" && others > 0) {
    const content = `<div class="callout">${escapeHtml(i18n.t("This signs out {count} other sessions and revokes their refresh access.", { count: others }))}</div><form method="post" action="/account/sessions/revoke-others" class="flow-form flow-form--single">${csrfField(data.csrfToken)}<div class="flow-actions"><button type="submit" class="btn btn--danger btn--auto">${escapeHtml(i18n.t("Sign out all other sessions"))}</button><a class="btn btn--ghost btn--auto" href="/?section=sessions">${escapeHtml(i18n.t("Cancel"))}</a></div></form>`
    return flowPanel(
      i18n,
      "Sign out other sessions?",
      "Review the sessions that will be signed out.",
      "Back to active sessions",
      dashboardHref("sessions"),
      content,
    )
  }
  return `<section class="dash-panel" id="sessions"><div class="dash-panel__head"><div><h2 class="dash-panel__title">${escapeHtml(i18n.t("Active sessions"))}</h2><p class="dash-panel__desc">${escapeHtml(i18n.t("Devices and browsers currently signed in to your account."))}</p></div></div><ul class="dash-list">${rows}</ul>${others === 0 ? "" : `<div class="dash-panel__foot dash-panel__foot--end"><a href="${escapeHtml(dashboardHref("sessions", { flow: "revoke-other-sessions" }))}" class="btn btn--ghost btn--sm">${escapeHtml(i18n.t("Sign out all other sessions"))}</a></div>`}</section>`
}

function renderAppsOverview(data: DashboardData): string {
  const { i18n } = data
  const rows = data.apps.map(
    (app) =>
      `<li class="dash-list__item"><div class="dash-item__main"><div class="dash-item__title">${escapeHtml(app.name)}</div><div class="dash-item__meta"><span class="dash-item__icon">${icons.key}</span><span class="mono">${app.scopes.map(escapeHtml).join(", ")}</span></div><div class="dash-item__meta">${escapeHtml(i18n.t("Resources:"))} <span class="mono">${app.resources.map(escapeHtml).join(", ")}</span></div></div><div class="dash-item__actions"><a class="btn btn--ghost btn--sm" href="${escapeHtml(dashboardHref("apps", { flow: "revoke-app", targetId: app.clientId }))}">${escapeHtml(i18n.t("Review access"))}</a></div></li>`,
  )
  const devices = data.devices.map(
    (device) =>
      `<li class="dash-list__item"><div class="dash-item__main"><div class="dash-item__title">${escapeHtml(device.clientName)}</div><div class="dash-item__meta"><span class="mono">${escapeHtml(device.resource)}</span> · ${escapeHtml(i18n.t("Last used"))} ${i18n.formatDate(device.lastRotatedAt)} · ${escapeHtml(i18n.t("Expires"))} ${i18n.formatDate(device.expiresAt)}</div></div><div class="dash-item__actions"><a class="btn btn--ghost btn--sm" href="${escapeHtml(dashboardHref("apps", { flow: "revoke-device", targetId: device.familyId }))}">${escapeHtml(i18n.t("Review device"))}</a></div></li>`,
  )
  return `<section class="dash-panel" id="apps"><div class="dash-panel__head"><div><h2 class="dash-panel__title">${escapeHtml(i18n.t("Authorized apps"))}</h2><p class="dash-panel__desc">${escapeHtml(i18n.t("Applications you have granted access to your account."))}</p></div></div><ul class="dash-list">${rows.length === 0 ? `<li class="dash-list__item--empty">${escapeHtml(i18n.t("No applications currently have access."))}</li>` : rows.join("\n")}</ul></section><section class="dash-panel" id="authorized-devices"><div class="dash-panel__head"><div><h2 class="dash-panel__title">${escapeHtml(i18n.t("Authorized CLI and devices"))}</h2><p class="dash-panel__desc">${escapeHtml(i18n.t("Refresh access issued independently to a device."))}</p></div></div><ul class="dash-list">${devices.length === 0 ? `<li class="dash-list__item--empty">${escapeHtml(i18n.t("No independent device access is active."))}</li>` : devices.join("\n")}</ul></section>`
}

function renderApps(data: DashboardData, view: DashboardView): string {
  const { i18n } = data
  if (view.flow === "revoke-app") {
    const app = data.apps.find((candidate) => candidate.clientId === view.targetId)
    if (app === undefined) return renderAppsOverview(data)
    const content = `<div class="meta"><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Application"))}</span><span class="meta__val">${escapeHtml(app.name)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Scopes"))}</span><span class="meta__val mono">${app.scopes.map(escapeHtml).join(", ")}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Resources"))}</span><span class="meta__val mono">${app.resources.map(escapeHtml).join(", ")}</span></div></div><div class="callout">${escapeHtml(i18n.t("This removes saved consent, authorization grants, and refresh access for this application."))}</div><form method="post" action="/account/apps/${encodeURIComponent(app.clientId)}/revoke" class="flow-form flow-form--single">${csrfField(data.csrfToken)}<div class="flow-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Revoke all access"))}</button><a class="btn btn--ghost btn--auto" href="/?section=apps">${escapeHtml(i18n.t("Cancel"))}</a></div></form>`
    return flowPanel(
      i18n,
      "Revoke application access?",
      "Review the grants and refresh access that will be removed.",
      "Back to authorized apps",
      dashboardHref("apps"),
      content,
    )
  }
  if (view.flow === "revoke-device") {
    const device = data.devices.find((candidate) => candidate.familyId === view.targetId)
    if (device === undefined) return renderAppsOverview(data)
    const content = `<div class="meta"><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Application"))}</span><span class="meta__val">${escapeHtml(device.clientName)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Resource"))}</span><span class="meta__val mono">${escapeHtml(device.resource)}</span></div><div class="meta__row"><span class="meta__key">${escapeHtml(i18n.t("Expires"))}</span><span class="meta__val mono">${escapeHtml(i18n.formatDate(device.expiresAt))}</span></div></div><div class="callout">${escapeHtml(i18n.t("This device will lose refresh access and must be authorized again."))}</div><form method="post" action="/account/devices/${encodeURIComponent(device.familyId)}/revoke" class="flow-form flow-form--single">${csrfField(data.csrfToken)}<div class="flow-actions"><button class="btn btn--danger btn--auto" type="submit">${escapeHtml(i18n.t("Revoke device"))}</button><a class="btn btn--ghost btn--auto" href="/?section=apps">${escapeHtml(i18n.t("Cancel"))}</a></div></form>`
    return flowPanel(
      i18n,
      "Revoke device access?",
      "Review this device before revoking its refresh access.",
      "Back to authorized apps",
      dashboardHref("apps"),
      content,
    )
  }
  return renderAppsOverview(data)
}

function renderAdmin(data: DashboardData): string {
  if (!data.isAdmin) return ""
  return `<section class="dash-panel" id="admin"><div class="dash-panel__head"><div><h2 class="dash-panel__title">${escapeHtml(data.i18n.t("Administration"))}</h2><p class="dash-panel__desc">${escapeHtml(data.i18n.t("Configure applications, users, resources, devices, and audit activity."))}</p></div><a href="/console" class="btn btn--primary btn--sm">${escapeHtml(data.i18n.t("Open admin console"))}</a></div></section>`
}

function renderSection(
  data: DashboardData,
  section: DashboardSection,
  view: DashboardView,
): string {
  switch (section) {
    case "profile":
      return renderProfile(data, view)
    case "login-methods":
      return renderLoginMethods(data, view)
    case "sessions":
      return renderSessions(data, view)
    case "apps":
      return renderApps(data, view)
    case "admin":
      return renderAdmin(data)
  }
}

const NOTICES: Readonly<Record<string, string>> = {
  profile_updated: "Profile saved.",
  avatar_updated: "Profile photo updated.",
  avatar_removed: "Profile photo removed.",
  avatar_too_large: "That photo is too large even after resizing. Choose a smaller image.",
  avatar_unsupported: "Choose a PNG, JPEG, WebP, or GIF image.",
  avatar_missing: "Choose an image file to upload.",
  avatar_rate_limited: "Too many photo uploads. Try again later.",
  password_added: "Password added.",
  password_renamed: "Password renamed.",
  password_invalid: "Check the new password policy and confirmation.",
  verification_sent: "Verification email sent.",
  email_verified: "Your email is already verified.",
  email_unavailable: "Email delivery is temporarily unavailable.",
  email_change_sent: "Check the new address to confirm your email change.",
  email_change_invalid: "Check the new email and current password, then try again.",
  passkey_added: "Passkey added.",
  passkey_renamed: "Passkey renamed.",
  session_revoked: "Session signed out.",
  sessions_revoked: "Other sessions signed out.",
  app_revoked: "Application access revoked.",
  device_revoked: "Device access revoked.",
  login_method_removed: "Login method removed.",
  last_login_method: "Add another password or passkey before removing this one.",
  delete_invalid: "Account deletion confirmation did not match.",
  last_active_admin: "Assign another active administrator before deleting this account.",
  invalid: "The request could not be verified.",
  not_found: "That item no longer exists.",
}

const SUCCESS_NOTICES = new Set([
  "profile_updated",
  "avatar_updated",
  "avatar_removed",
  "password_added",
  "password_renamed",
  "login_method_removed",
  "verification_sent",
  "email_verified",
  "email_change_sent",
  "passkey_added",
  "passkey_renamed",
  "session_revoked",
  "sessions_revoked",
  "app_revoked",
  "device_revoked",
])

const DASHBOARD_STYLES = `
.stage{padding-top:1rem;padding-bottom:1.5rem}
.shell{gap:1rem;padding-top:0}
.shell-main{gap:1rem}
.action-list{display:flex;flex-direction:column;margin-top:1.1rem;border:1px solid var(--line);border-radius:var(--r-field);overflow:hidden}
.profile-summary{margin-top:1.5rem}
.profile-summary>.identity__body{flex:1}
.profile-summary>.btn{flex:none}
.meta__row--identity .meta__key{flex:none}
.meta__row--identity .meta__val{min-width:0}
.meta__val--email{display:flex;align-items:center;justify-content:flex-end;gap:.5rem;flex-wrap:wrap;min-width:0}
.meta__email{min-width:0;overflow-wrap:anywhere}
.group-list{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:.35rem}
.group-chip{display:inline-flex;align-items:center;max-width:100%;padding:.16rem .5rem;border:1px solid var(--line-2);border-radius:var(--r-pill);background:var(--surface-3);color:var(--ink-2);font-size:.72rem;font-weight:600;line-height:1.35;overflow-wrap:anywhere}
.action-row{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.9rem 1rem;background:var(--surface)}
.action-row+.action-row{border-top:1px solid var(--line)}
.action-row h3,.choice-row h3,.manage-form h3,.passkey-setup h3{margin:0;font-size:.9rem}
.action-row p,.choice-row p,.manage-form p,.passkey-setup p{margin:.18rem 0 0;color:var(--ink-2);font-size:.8rem;line-height:1.45}
.action-row--danger{background:color-mix(in srgb,var(--danger-bg) 35%,var(--surface))}
.action-row__actions{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;justify-content:flex-end}
.btn--auto{width:auto}
.flow-page{display:grid;min-width:0;gap:1rem}
.flow-page>.flow-back{justify-self:start}
.flow-panel{width:100%}
.flow-panel__head{align-items:flex-start;padding:1rem 1.25rem .85rem;border-bottom:1px solid var(--line)}
.flow-panel__body{max-width:none;padding:1rem 1.25rem 1.1rem}
.flow-back{display:inline-flex;font-size:.77rem}
.flow-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.7rem;max-width:none}
.flow-form--single{grid-template-columns:minmax(0,1fr)}
.flow-form .field{margin:0}
.flow-form>.callout{grid-column:1/-1}
.flow-panel .input{padding:.58rem .75rem;font-size:.92rem}
.flow-actions{display:flex;align-items:center;justify-content:flex-start;padding-top:.05rem}
.readonly-field{display:grid;gap:.18rem;margin-bottom:.9rem;padding:.78rem .9rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}
.readonly-field>span{font-size:.72rem;color:var(--ink-3)}
.readonly-field>small{font-size:.76rem;color:var(--ink-2)}
.flow-steps{margin:0 0 1rem;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;overflow:hidden;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field)}
.flow-step{display:flex;align-items:flex-start;gap:.62rem;padding:.7rem .8rem;background:var(--surface-2);color:var(--ink-3)}
.flow-step>span{display:grid;place-items:center;flex:none;width:1.4rem;height:1.4rem;border:1px solid var(--line-2);border-radius:50%;font:600 .66rem/1 var(--font-mono)}
.choice-list{display:grid;gap:1px;overflow:hidden;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field)}
.choice-row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:.85rem;padding:.9rem;color:var(--ink);background:var(--surface-2)}
.choice-row:hover{text-decoration:none;background:var(--surface-3)}
.choice-row>span{color:var(--brass);font-size:.78rem;font-weight:600}
.method-mark{display:grid;place-items:center;flex:none;width:34px;height:34px;border-radius:9px;color:var(--brass);background:var(--brass-soft);border:1px solid var(--brass-line)}
.method-mark svg{width:18px;height:18px}
.method-mark--passkey{color:var(--ok);background:var(--ok-soft);border-color:transparent}
.method-kind{font-size:.63rem;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-3);border:1px solid var(--line-2);border-radius:var(--r-pill);padding:.07rem .34rem}
.method-warning{margin-top:.35rem;color:var(--brass);font-size:.76rem;line-height:1.4}
.passkey-setup{display:grid;gap:.85rem}
.passkey-setup__intro{display:flex;align-items:center;gap:.75rem;padding:.78rem .85rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}
.credential-summary{display:flex;align-items:center;gap:.75rem;margin-bottom:.85rem;padding:.75rem .82rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}
.credential-summary>div:last-child{display:grid}
.credential-summary span{color:var(--ink-2);font-size:.76rem}
.manage-stack{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(220px,.8fr);gap:1px;margin-top:.85rem;overflow:hidden;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field)}
.manage-form{align-content:start;padding:.95rem 1rem;background:var(--surface)}
.manage-form--danger{display:flex;flex-direction:column;background:color-mix(in srgb,var(--danger-bg) 32%,var(--surface))}
.manage-form--danger .flow-actions{margin-top:auto;padding-top:.7rem}
.form-hint{margin:0;color:var(--ink-2);font-size:.76rem}
.inline-status{margin:.7rem 0 0;color:var(--ink-2);font-size:.8rem}
.inline-status--error{color:var(--danger)}
.inline-status--ok{color:var(--ok)}
.profile-edit-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;overflow:hidden;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field)}
.profile-edit-grid>form{align-content:start;padding:1rem;background:var(--surface)}
.profile-name-form .form-actions{align-self:end}
.avatar-editor{display:flex;align-items:center;gap:1rem}
.avatar-editor__body{flex:1;min-width:0}
.avatar-editor__body small{display:block;margin-top:.3rem;color:var(--ink-2);font-size:.75rem}
.avatar--lg{width:64px;height:64px;font-size:1.3rem}
.avatar-form{align-content:start}
.avatar-crop{display:grid;justify-items:center;gap:.7rem;margin-top:.3rem}
.avatar-crop[hidden]{display:none}
.avatar-crop__canvas{max-width:100%;height:auto;border:1px solid var(--line-brass);border-radius:var(--r-field);background:var(--surface-3);touch-action:none;cursor:crosshair}
.avatar-crop__canvas:focus-visible{outline:none;box-shadow:var(--focus)}
.avatar-crop__hint{margin:0;color:var(--ink-2);font-size:.75rem;text-align:center}
.dash-notice{padding:.75rem .9rem;color:var(--ok);background:var(--ok-soft);border:1px solid rgba(121,211,165,.25);border-radius:var(--r-field)}
.dash-notice--error{color:var(--danger);background:var(--danger-soft);border-color:var(--danger-line)}
@media(max-width:720px){
  .flow-panel__head{padding:1rem 1.05rem .9rem}
  .flow-panel__body{padding:1rem 1.05rem 1.1rem}
  .flow-form,.profile-edit-grid{grid-template-columns:1fr}
  .flow-form>.security-note,.flow-form>.callout,.flow-form>.form-hint,.flow-form>.form-actions{grid-column:auto}
  .flow-steps{grid-template-columns:1fr}
  .manage-stack{grid-template-columns:1fr}
  .choice-row{grid-template-columns:auto minmax(0,1fr)}
  .flow-form>.callout,.flow-form>.form-hint,.flow-form>.form-actions{grid-column:auto}
  .action-row{align-items:flex-start;flex-direction:column}
  .action-row__actions{justify-content:flex-start;width:100%}
  .flow-actions .btn{width:100%}
  .dash-list__item .method-mark{display:none}
}
@media(max-width:480px){
  .profile-summary{gap:.6rem;padding:.7rem}
  .profile-summary .avatar{width:38px;height:38px;font-size:.9rem}
  .profile-summary .identity__name{font-size:.9rem}
  .profile-summary .identity__sub{font-size:.75rem}
  .profile-summary>.btn{padding:.4rem .55rem;font-size:.78rem}
}
`

export function renderDashboard(
  data: DashboardData,
  section: DashboardSection,
  view: DashboardView,
): string {
  const { i18n } = data
  const displayName = data.user.name ?? data.user.alias
  const heading = i18n.t(
    NAV_ITEMS.find((item) => item.section === section)?.label ?? "Your account",
  )
  const avatar = avatarMarkup(data.user)
  const tabs = NAV_ITEMS.filter((item) => item.section !== "admin" || data.isAdmin).map((item) => ({
    label: i18n.t(item.label),
    href: dashboardHref(item.section),
    active: item.section === section,
  }))
  const barRight = `<div class="shell-user">${avatar}<span class="shell-user__name">${escapeHtml(displayName)}</span></div><form method="post" action="/logout">${csrfField(data.csrfToken)}<button type="submit" class="btn btn--ghost btn--sm">${escapeHtml(i18n.t("Sign out"))}</button></form>`
  const notice = data.notice === undefined ? undefined : NOTICES[data.notice]
  const success = data.notice !== undefined && SUCCESS_NOTICES.has(data.notice)
  const noticeHtml =
    notice === undefined
      ? ""
      : `<div class="dash-notice${success ? "" : " dash-notice--error"}" role="${success ? "status" : "alert"}">${escapeHtml(i18n.t(notice))}</div>`

  return appShell({
    i18n,
    title: i18n.t("Your account — KeyForge"),
    heading,
    barRight,
    tabs,
    content: `${noticeHtml}${renderSection(data, section, view)}`,
    extraStyles: DASHBOARD_STYLES,
  })
}
