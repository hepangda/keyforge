import type { I18n } from "../i18n"
import { brandHeader, escapeHtml, htmlLayout, icons } from "./layout"

export type LoginPageParams = {
  readonly i18n: I18n
  readonly csrfToken: string
  readonly returnTo: string
  readonly email?: string
  readonly error?: string
  readonly reauthenticating?: boolean
}

function alertBox(message: string): string {
  return `<div class="alert" role="alert">${icons.alert}<div>${escapeHtml(message)}</div></div>`
}

export function renderLoginPage(params: LoginPageParams): string {
  const { i18n } = params
  const error = params.error === undefined ? "" : alertBox(params.error)
  const magicQuery = new URLSearchParams()
  if (params.returnTo && params.returnTo !== "/") magicQuery.set("return_to", params.returnTo)
  if (params.reauthenticating === true) magicQuery.set("reauth", "1")
  const magicHref = `/login/magic${magicQuery.size === 0 ? "" : `?${magicQuery.toString()}`}`
  const alternatives = `<button class="btn btn--ghost" type="button" data-passkey-login data-return-to="${escapeHtml(params.returnTo)}" data-waiting-message="${escapeHtml(i18n.t("Waiting for your passkey…"))}" data-cancelled-message="${escapeHtml(i18n.t("Passkey sign-in was cancelled."))}" data-error-message="${escapeHtml(i18n.t("Passkey sign-in could not be completed."))}"${params.reauthenticating === true ? ' data-reauth="1"' : ""}>${escapeHtml(i18n.t("Use a passkey"))}</button>`
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t(params.reauthenticating === true ? "Sign in again" : "Sign in to KeyForge"))}</h1>
    <p class="lead">${escapeHtml(i18n.t(params.reauthenticating === true ? "The application requested fresh authentication before continuing." : "Enter your credentials to continue to your account."))}</p>
  </div>
  ${error}
  <form method="post" action="/login" autocomplete="on">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    <input type="hidden" name="return_to" value="${escapeHtml(params.returnTo)}">
    ${params.reauthenticating === true ? '<input type="hidden" name="reauth" value="1">' : ""}
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("Email or username"))}</span>
      <input class="input" type="text" name="email" required autocomplete="username"
        autofocus autocapitalize="none" spellcheck="false"
        value="${escapeHtml(params.email ?? "")}">
    </label>
    <div class="field">
      <span class="field__row"><label class="field__label" for="login-password">${escapeHtml(i18n.t("Password"))}</label><a href="/password/forgot">${escapeHtml(i18n.t("Forgot password?"))}</a></span>
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
    ".field__row{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}.field__row .field__label{margin:0}.field__row a{font-size:.78rem}.inline-status{margin:.8rem 0 0;color:var(--ink-2);font-size:.84rem;text-align:center}",
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
