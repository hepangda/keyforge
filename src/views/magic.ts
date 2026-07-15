import type { I18n } from "../i18n"
import { brandHeader, escapeHtml, htmlLayout, icons } from "./layout"

const MAIL_ICON = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2.5" stroke="currentColor" stroke-width="1.8"/><path d="m4 7 8 6 8-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`

export function renderMagicRequestPage(
  i18n: I18n,
  csrfToken: string,
  returnTo: string,
  reauthenticating = false,
  error?: string,
): string {
  const errorHtml =
    error === undefined
      ? ""
      : `<div class="alert" role="alert">${icons.alert}<div>${escapeHtml(i18n.t(error))}</div></div>`
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Sign in with email"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("We'll email you a secure link to sign in — no password needed."))}</p>
  </div>
  ${errorHtml}
  <form method="post" action="/login/magic" autocomplete="on">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    ${reauthenticating ? '<input type="hidden" name="reauth" value="1">' : ""}
    <label class="field">
      <span class="field__label">${escapeHtml(i18n.t("Email"))}</span>
      <input class="input" type="email" name="email" required autocomplete="username"
        autocapitalize="none" spellcheck="false" autofocus placeholder="you@example.com">
    </label>
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Email me a link"))}</button>
  </form>
  <p class="foot foot--split"><a class="link-quiet" href="/login">${escapeHtml(i18n.t("Back to password sign-in"))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Sign in with email — KeyForge"), body)
}

export function renderMagicSentPage(i18n: I18n, email: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark">${MAIL_ICON}</div>
    <h1>${escapeHtml(i18n.t("Check your email"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("If an account exists for {email}, a sign-in link is on its way.", { email }))}</p>
  </div>
  <div class="callout">${escapeHtml(i18n.t("The link expires in 15 minutes. You can close this tab after opening it."))}</div>
</main>`
  return htmlLayout(i18n, i18n.t("Check your email — KeyForge"), body)
}

export function renderMagicConfirmation(
  i18n: I18n,
  csrfToken: string,
  token: string,
  email: string,
): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(i18n.t("Confirm sign in"))}</h1>
    <p class="lead">${escapeHtml(i18n.t("Continue as {email}.", { email }))}</p>
  </div>
  <form method="post" action="/login/magic/callback">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <input type="hidden" name="token" value="${escapeHtml(token)}">
    <button class="btn btn--primary" type="submit">${escapeHtml(i18n.t("Sign in"))}</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/login">${escapeHtml(i18n.t("Cancel"))}</a></p>
</main>`
  return htmlLayout(i18n, i18n.t("Confirm sign in — KeyForge"), body)
}
