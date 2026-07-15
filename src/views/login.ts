import { brandHeader, escapeHtml, htmlLayout, icons } from "./layout"

export type LoginPageParams = {
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
  const error = params.error === undefined ? "" : alertBox(params.error)
  const magicQuery = new URLSearchParams()
  if (params.returnTo && params.returnTo !== "/") magicQuery.set("return_to", params.returnTo)
  if (params.reauthenticating === true) magicQuery.set("reauth", "1")
  const magicHref = `/login/magic${magicQuery.size === 0 ? "" : `?${magicQuery.toString()}`}`
  const alternatives = `<button class="btn btn--ghost" type="button" data-passkey-login data-return-to="${escapeHtml(params.returnTo)}"${params.reauthenticating === true ? ' data-reauth="1"' : ""}>Use a passkey</button>`
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>${params.reauthenticating === true ? "Sign in again" : "Sign in to KeyForge"}</h1>
    <p class="lead">${params.reauthenticating === true ? "The application requested fresh authentication before continuing." : "Enter your credentials to continue to your account."}</p>
  </div>
  ${error}
  <form method="post" action="/login" autocomplete="on">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    <input type="hidden" name="return_to" value="${escapeHtml(params.returnTo)}">
    ${params.reauthenticating === true ? '<input type="hidden" name="reauth" value="1">' : ""}
    <label class="field">
      <span class="field__label">Email or username</span>
      <input class="input" type="text" name="email" required autocomplete="username"
        autofocus autocapitalize="none" spellcheck="false"
        value="${escapeHtml(params.email ?? "")}">
    </label>
    <div class="field">
      <span class="field__row"><label class="field__label" for="login-password">Password</label><a href="/password/forgot">Forgot password?</a></span>
      <input class="input" id="login-password" type="password" name="password" required autocomplete="current-password">
    </div>
    <button class="btn btn--primary" type="submit">Sign in</button>
  </form>
  <div class="rule">or</div>
  <div class="stack">${alternatives}</div>
  <p class="inline-status" data-passkey-status role="status" hidden></p>
  <p class="foot"><a class="link-quiet" href="${escapeHtml(magicHref)}">Email me a sign-in link instead</a></p>
  <script src="/assets/login.js" defer></script>
</main>`
  return htmlLayout(
    "Sign in — KeyForge",
    body,
    ".field__row{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}.field__row .field__label{margin:0}.field__row a{font-size:.78rem}.inline-status{margin:.8rem 0 0;color:var(--ink-2);font-size:.84rem;text-align:center}",
  )
}

export function renderLogoutConfirmation(csrfToken: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>Sign out?</h1>
    <p class="lead">This browser session will end. Other signed-in devices remain active.</p>
  </div>
  <form method="post" action="/logout">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <button class="btn btn--primary" type="submit">Sign out</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/">Cancel and return to your account</a></p>
</main>`
  return htmlLayout("Sign out — KeyForge", body)
}

export function renderEndSessionConfirmation(
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
  const destination = clientName === null ? "the requesting application" : clientName
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>Sign out?</h1>
    <p class="lead">${escapeHtml(destination)} requested that this browser session end. Other signed-in devices remain active.</p>
  </div>
  <form method="post" action="/oauth/end_session">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    ${hidden}
    <button class="btn btn--primary" type="submit">Sign out and continue</button>
  </form>
  <p class="foot"><a class="link-quiet" href="/">Cancel and return to your account</a></p>
</main>`
  return htmlLayout("Sign out — KeyForge", body)
}
