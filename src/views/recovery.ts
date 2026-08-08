import type { I18n, MessageValues } from "../i18n"
import { brandHeader, continuationHref, escapeHtml, htmlLayout, icons } from "./layout"

function alert(i18n: I18n, message?: string): string {
  return message === undefined
    ? ""
    : `<div class="alert" role="alert">${icons.alert}<div>${escapeHtml(i18n.t(message))}</div></div>`
}

export function renderPasswordResetRequest(
  i18n: I18n,
  csrfToken: string,
  returnTo: string,
  reauthenticating: boolean,
  error?: string,
  email = "",
  hint?: string,
): string {
  const body = `<div class="card-page"><a class="btn btn--ghost btn--sm btn--auto back-link" href="${escapeHtml(continuationHref("/login", returnTo, reauthenticating, hint))}">${escapeHtml(i18n.t("Back to sign in"))}</a><main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Reset your password"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("Enter your account email and we'll send a one-time reset link."))}</p>
  </div>
  ${alert(i18n, error)}
  <form method="post" action="/password/forgot">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    ${reauthenticating ? '<input type="hidden" name="reauth" value="1">' : ""}
    ${hint === undefined ? "" : `<input type="hidden" name="hint" value="${escapeHtml(hint)}">`}
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("Email"))}</span>
      <input class="input" type="email" name="email" autocomplete="username" required autofocus value="${escapeHtml(email)}">
    </label>
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Send reset link"))}</button>
  </form>
</main></div>`
  return htmlLayout(i18n, i18n.t("Reset password — KeyForge"), body)
}

export function renderPasswordResetSent(
  i18n: I18n,
  email: string,
  returnTo: string,
  reauthenticating: boolean,
  hint?: string,
): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark">${icons.check}</div>
    <h1>${escapeHtml(i18n.t("Check your email"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("If an account exists for {email}, a reset link is on its way.", { email }))}</p>
  </div>
  <div class="callout">${escapeHtml(i18n.t("The link expires in one hour and works only once."))}</div>
  <p class="form-hint">${escapeHtml(i18n.t("Check your spam folder if the email doesn't arrive. You can request another link after it expires."))}</p>
  <p class="foot"><a class="link-quiet" href="${escapeHtml(continuationHref("/login", returnTo, reauthenticating, hint))}">${escapeHtml(i18n.t("Return to sign in"))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Check your email — KeyForge"), body)
}

export function renderPasswordResetForm(
  i18n: I18n,
  csrfToken: string,
  token: string,
  minimumLength: number,
  error?: string,
  invitation = false,
): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t(invitation ? "Accept your invitation" : "Choose a new password"))}</h1>
    <p class="lead">${escapeHtml(invitation ? i18n.t("Create a password to activate your invited account.") : i18n.t("Use at least {minimum} characters and avoid a password used elsewhere.", { minimum: minimumLength }))}</p>
  </div>
  ${alert(i18n, error)}
  <form method="post" action="/password/reset">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <input type="hidden" name="token" value="${escapeHtml(token)}">
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("New password"))}</span>
      <input class="input" type="password" name="password" minlength="${minimumLength}" maxlength="128" autocomplete="new-password" required autofocus>
    </label>
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("Confirm new password"))}</span>
      <input class="input" type="password" name="password_confirm" minlength="${minimumLength}" maxlength="128" autocomplete="new-password" required>
    </label>
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t(invitation ? "Accept invitation" : "Reset password"))}</button>
  </form>
</main>`
  return htmlLayout(
    i18n,
    i18n.t(invitation ? "Accept invitation — KeyForge" : "Choose a new password — KeyForge"),
    body,
  )
}

export function renderRecoveryResult(
  i18n: I18n,
  title: string,
  message: string,
  success: boolean,
  actionHref: string,
  actionLabel: string,
): string {
  const mark = success ? icons.check : icons.cross
  const muted = success ? "" : " result-mark--muted"
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark${muted}">${mark}</div>
    <h1>${escapeHtml(i18n.t(title))}</h1>
    <p class="lead">${escapeHtml(i18n.t(message))}</p>
  </div>
  <p class="foot"><a class="link-quiet" href="${escapeHtml(actionHref)}">${escapeHtml(i18n.t(actionLabel))}</a></p>
</main>`
  return htmlLayout(i18n, `${i18n.t(title)} — KeyForge`, body)
}

export function renderRecoveryConfirmation(params: {
  readonly i18n: I18n
  readonly title: string
  readonly message: string
  readonly messageValues?: MessageValues
  readonly action: string
  readonly token: string
  readonly csrfToken: string
  readonly submitLabel: string
}): string {
  const { i18n } = params
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t(params.title))}</h1>
    <p class="lead">${escapeHtml(i18n.t(params.message, params.messageValues))}</p>
  </div>
  <form method="post" action="${escapeHtml(params.action)}">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    <input type="hidden" name="token" value="${escapeHtml(params.token)}">
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t(params.submitLabel))}</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/login">${escapeHtml(i18n.t("Cancel"))}</a></p>
</main>`
  return htmlLayout(i18n, `${i18n.t(params.title)} — KeyForge`, body)
}
