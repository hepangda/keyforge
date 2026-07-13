import { brandHeader, escapeHtml, htmlLayout, icons } from "./layout"

function alert(message?: string): string {
  return message === undefined
    ? ""
    : `<div class="alert" role="alert">${icons.alert}<div>${escapeHtml(message)}</div></div>`
}

export function renderPasswordResetRequest(csrfToken: string, error?: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>Reset your password</h1>
    <p class="lead">Enter your account email and we'll send a one-time reset link.</p>
  </div>
  ${alert(error)}
  <form method="post" action="/password/forgot">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <label class="field">
      <span class="field__label">Email</span>
      <input class="input" type="email" name="email" autocomplete="username" required autofocus>
    </label>
    <button class="btn btn--primary" type="submit">Send reset link</button>
  </form>
  <p class="foot foot--split"><a class="link-quiet" href="/login">Back to sign in</a></p>
</main>`
  return htmlLayout("Reset password — KeyForge", body)
}

export function renderPasswordResetSent(email: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark">${icons.check}</div>
    <h1>Check your email</h1>
    <p class="lead">If an account exists for <strong>${escapeHtml(email)}</strong>, a reset link is on its way.</p>
  </div>
  <div class="callout">The link expires in <strong>one hour</strong> and works only once.</div>
  <p class="foot"><a class="link-quiet" href="/login">Return to sign in</a></p>
</main>`
  return htmlLayout("Check your email — KeyForge", body)
}

export function renderPasswordResetForm(
  csrfToken: string,
  token: string,
  error?: string,
  invitation = false,
): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${invitation ? "Accept your invitation" : "Choose a new password"}</h1>
    <p class="lead">${invitation ? "Create a password to activate your invited account." : "Use at least 12 characters and avoid a password used elsewhere."}</p>
  </div>
  ${alert(error)}
  <form method="post" action="/password/reset">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <input type="hidden" name="token" value="${escapeHtml(token)}">
    <label class="field">
      <span class="field__label">New password</span>
      <input class="input" type="password" name="password" minlength="12" maxlength="128" autocomplete="new-password" required autofocus>
    </label>
    <label class="field">
      <span class="field__label">Confirm new password</span>
      <input class="input" type="password" name="password_confirm" minlength="12" maxlength="128" autocomplete="new-password" required>
    </label>
    <button class="btn btn--primary" type="submit">${invitation ? "Accept invitation" : "Reset password"}</button>
  </form>
</main>`
  return htmlLayout(
    `${invitation ? "Accept invitation" : "Choose a new password"} — KeyForge`,
    body,
  )
}

export function renderRecoveryResult(title: string, message: string, success: boolean): string {
  const mark = success ? icons.check : icons.cross
  const muted = success ? "" : " result-mark--muted"
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark${muted}">${mark}</div>
    <h1>${escapeHtml(title)}</h1>
    <p class="lead">${escapeHtml(message)}</p>
  </div>
  <p class="foot"><a class="link-quiet" href="/login">Continue to sign in</a></p>
</main>`
  return htmlLayout(`${title} — KeyForge`, body)
}

export function renderRecoveryConfirmation(params: {
  readonly title: string
  readonly message: string
  readonly action: string
  readonly token: string
  readonly csrfToken: string
  readonly submitLabel: string
}): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${escapeHtml(params.title)}</h1>
    <p class="lead">${escapeHtml(params.message)}</p>
  </div>
  <form method="post" action="${escapeHtml(params.action)}">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    <input type="hidden" name="token" value="${escapeHtml(params.token)}">
    <button class="btn btn--primary" type="submit">${escapeHtml(params.submitLabel)}</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/login">Cancel</a></p>
</main>`
  return htmlLayout(`${params.title} — KeyForge`, body)
}
