import { brandHeader, escapeHtml, htmlLayout, icons, permissionList } from "./layout"

export type ConsentPageParams = {
  readonly csrfToken: string
  readonly clientName: string
  readonly scopes: readonly string[]
  readonly resource: string
  readonly hiddenFields: Readonly<Record<string, string>>
}

export function renderConsentPage(params: ConsentPageParams): string {
  const hidden = Object.entries(params.hiddenFields)
    .map(
      ([key, value]) =>
        `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`,
    )
    .join("\n  ")
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <h1>Authorize ${escapeHtml(params.clientName)}</h1>
    <p class="lead"><strong>${escapeHtml(params.clientName)}</strong> wants to access your KeyForge account.</p>
  </div>
  ${permissionList(params.scopes)}
  <div class="callout">Resource <span class="mono">${escapeHtml(params.resource)}</span></div>
  <form method="post" action="/oauth/authorize/decision">
    <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">
    ${hidden}
    <div class="btn-row">
      <button class="btn btn--ghost" type="submit" name="decision" value="deny">Deny</button>
      <button class="btn btn--primary" type="submit" name="decision" value="approve">Allow access</button>
    </div>
  </form>
</main>`
  return htmlLayout("Authorize — KeyForge", body)
}

export function renderErrorPage(description: string): string {
  const body = `<main class="card">
  <div class="head">
    ${brandHeader()}
    <div class="result-mark result-mark--muted">${icons.cross}</div>
    <h1>Request error</h1>
  </div>
  <div class="alert" role="alert">${icons.alert}<div>${escapeHtml(description)}</div></div>
  <p class="foot"><a class="link-quiet" href="/login">Return to sign in</a></p>
</main>`
  return htmlLayout("Error — KeyForge", body)
}
