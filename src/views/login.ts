import type { I18n } from "../i18n"
import { brandHeader, continuationHref, escapeHtml, htmlLayout, icons } from "./layout"

export type LoginPageParams = {
  readonly i18n: I18n
  readonly csrfToken: string
  readonly returnTo: string
  readonly email?: string
  readonly error?: string
  readonly reauthenticating?: boolean
  readonly hint?: string
  readonly clientName?: string
}

const REAUTH_HINT_MESSAGES: Readonly<Record<string, string>> = {
  add_password: "Adding a password to your account requires a fresh sign-in.",
  manage_password: "Managing your password requires a fresh sign-in.",
  add_passkey: "Adding a passkey to your account requires a fresh sign-in.",
  manage_passkey: "Managing your passkey requires a fresh sign-in.",
  change_email: "Changing your email address requires a fresh sign-in.",
  delete_account: "Deleting your account permanently requires a fresh sign-in.",
  admin_action: "Admin console management actions require a recent sign-in.",
  authorize_device: "Authorizing a device requires a fresh sign-in.",
  oauth_request: "The requesting application requires a fresh sign-in.",
}

function alertBox(message: string): string {
  return `<div class="alert" role="alert">${icons.alert}<div>${escapeHtml(message)}</div></div>`
}

export function renderLoginPage(params: LoginPageParams): string {
  const { i18n } = params
  const isReauth = params.reauthenticating === true
  const hintMessage =
    isReauth && params.hint !== undefined
      ? (REAUTH_HINT_MESSAGES[params.hint] ??
        "For your security, please confirm your identity to continue.")
      : isReauth
        ? "For your security, please confirm your identity to continue."
        : "Enter your credentials to continue to your account."
  const error = params.error === undefined ? "" : alertBox(params.error)
  const reauthContext =
    !isReauth || params.clientName === undefined
      ? ""
      : `<div class="reauth-context"><span>${escapeHtml(i18n.t("Requested by"))}</span><strong>${escapeHtml(params.clientName)}</strong></div>`
  const magicHref = continuationHref("/login/magic", params.returnTo, isReauth, params.hint)
  const forgotHref = continuationHref("/password/forgot", params.returnTo, isReauth, params.hint)
  const alternatives = `<button class="btn btn--ghost" type="button" data-passkey-login data-hint="${escapeHtml(params.hint ?? "")}" data-return-to="${escapeHtml(params.returnTo)}" data-waiting-message="${escapeHtml(i18n.t("Waiting for your passkey…"))}" data-cancelled-message="${escapeHtml(i18n.t("Passkey sign-in was cancelled."))}" data-error-message="${escapeHtml(i18n.t("Passkey sign-in could not be completed."))}" data-network-error-message="${escapeHtml(i18n.t("Could not reach the server. Check your connection and try again."))}" data-rate-limited-message="${escapeHtml(i18n.t("Too many attempts. Please wait and try again."))}"${isReauth ? ' data-reauth="1"' : ""} hidden>${escapeHtml(i18n.t("Use a passkey"))}</button>`
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t(isReauth ? "Sign in again" : "Sign in to KeyForge"))}</h1>
    <p class="lead">${escapeHtml(i18n.t(hintMessage))}</p>
  </div>
  ${error}
  ${reauthContext}
  <form method="post" action="/login" autocomplete="on">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    <input type="hidden" name="return_to" value="${escapeHtml(params.returnTo)}">
    ${isReauth ? '<input type="hidden" name="reauth" value="1">' : ""}
    ${params.hint === undefined ? "" : `<input type="hidden" name="hint" value="${escapeHtml(params.hint)}">`}
    ${params.clientName === undefined ? "" : `<input type="hidden" name="client_name" value="${escapeHtml(params.clientName)}">`}
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("Email or username"))}</span>
      <input class="input" type="text" name="email" required autocomplete="username"
        autofocus autocapitalize="none" spellcheck="false"
        value="${escapeHtml(params.email ?? "")}">
    </label>
    <div class="field">
      <span class="field__row"><label class="field__label" for="login-password">${escapeHtml(i18n.t("Password"))}</label><a href="${escapeHtml(forgotHref)}">${escapeHtml(i18n.t("Forgot password?"))}</a></span>
      <input class="input" id="login-password" type="password" name="password" required autocomplete="current-password">
    </div>
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Sign in"))}</button>
  </form>
  <div class="rule">${escapeHtml(i18n.t("or"))}</div>
  <div class="stack">${alternatives}</div>
  <p class="inline-status" data-passkey-status role="status" hidden></p>
  <p class="foot"><a class="link-quiet" href="${escapeHtml(magicHref)}">${escapeHtml(i18n.t("Email me a sign-in link instead"))}</a></p>
  <script src="/assets/login.js" defer></script>
</main>`
  return htmlLayout(
    i18n,
    i18n.t("Sign in — KeyForge"),
    body,
    ".reauth-context{display:grid;gap:.12rem;margin:0 0 1rem;padding:.72rem .82rem;background:var(--brass-soft);border:1px solid var(--brass-line);border-radius:var(--r-chip)}.reauth-context span{color:var(--ink-3);font-size:.72rem}.reauth-context strong{color:var(--ink);font-size:.9rem;overflow-wrap:anywhere}.field__row{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}.field__row .field__label{margin:0}.field__row a{font-size:.78rem}.inline-status{margin:.8rem 0 0;color:var(--ink-2);font-size:.84rem;text-align:center}",
  )
}

export function renderLogoutConfirmation(i18n: I18n, csrfToken: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Sign out?"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("This browser session will end. Other signed-in devices remain active."))}</p>
  </div>
  <form method="post" action="/logout">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Sign out"))}</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/">${escapeHtml(i18n.t("Cancel and return to your account"))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Sign out — KeyForge"), body)
}

export function renderEndSessionConfirmation(
  i18n: I18n,
  csrfToken: string,
  params: URLSearchParams,
  clientName: string | null,
): string {
  const hidden = ["id_token_hint", "client_id", "post_logout_redirect_uri", "state"]
    .map((name) => {
      const value = params.get(name)
      return value === null
        ? ""
        : `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`
    })
    .join("")
  const destination = clientName === null ? i18n.t("the requesting application") : clientName
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Sign out?"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("{application} requested that this browser session end. Other signed-in devices remain active.", { application: destination }))}</p>
  </div>
  <form method="post" action="/oauth/end_session">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    ${hidden}
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Sign out and continue"))}</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/">${escapeHtml(i18n.t("Cancel and return to your account"))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Sign out — KeyForge"), body)
}
