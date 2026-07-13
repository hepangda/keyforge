import { appShell, brandHeader, escapeHtml, htmlLayout } from "../layout"

export type ConsoleSection = "overview" | "users" | "clients" | "resources" | "devices" | "audit"

export type ConsoleFlash = { readonly kind: "ok" | "warn"; readonly message: string }

export type ConsoleChrome = {
  readonly section: ConsoleSection
  readonly adminEmail: string
  readonly flash?: ConsoleFlash
}

const TABS: readonly {
  readonly section: ConsoleSection
  readonly label: string
  readonly href: string
}[] = [
  { section: "overview", label: "Overview", href: "/console" },
  { section: "users", label: "Users", href: "/console/users" },
  { section: "clients", label: "Clients", href: "/console/clients" },
  { section: "resources", label: "Resources", href: "/console/resources" },
  { section: "devices", label: "Devices", href: "/console/devices" },
  { section: "audit", label: "Audit", href: "/console/audit" },
]

const CONSOLE_STYLES = `
.flash{display:flex;align-items:center;gap:.6rem;padding:.75rem 1rem;border-radius:var(--r-field);font-size:.9rem}
.flash--ok{color:var(--ok);background:var(--ok-soft);border:1px solid transparent}
.flash--warn{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line)}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);box-shadow:var(--shadow);overflow:hidden;min-width:0}
.panel__head{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding:1.25rem 1.5rem;border-bottom:1px solid var(--line)}
.panel__title{margin:0;font-size:1.08rem;font-weight:640;letter-spacing:-.01em}
.panel__desc{margin:.2rem 0 0;font-size:.85rem;color:var(--ink-2)}
.panel__body{padding:1.4rem 1.5rem}
.panel__body>.flash{margin-bottom:1rem}
.ctable-wrap{overflow-x:auto}
.ctable{width:100%;min-width:620px;border-collapse:collapse;font-size:.87rem}
.ctable th{text-align:left;padding:.7rem 1.5rem;font-size:.7rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3);background:var(--surface-2);border-bottom:1px solid var(--line);white-space:nowrap}
.ctable td{padding:.85rem 1.5rem;border-bottom:1px solid var(--line);vertical-align:middle;color:var(--ink)}
.ctable tbody tr:last-child td{border-bottom:0}
.ctable tbody tr:hover td{background:var(--surface-2)}
.ctable .mono{font-family:var(--font-mono);font-size:.82rem;color:var(--ink-2)}
.ctable__value{min-width:0;overflow-wrap:anywhere}
.ctable__empty{padding:2.5rem 1.5rem;text-align:center;color:var(--ink-2)}
.actions{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;justify-content:flex-end}
.actions--start{justify-content:flex-start}
.secret-done{margin-top:1.2rem}
.tag{display:inline-block;font-family:var(--font-mono);font-size:.74rem;color:var(--ink-2);background:var(--surface-3);border:1px solid var(--line-2);border-radius:var(--r-chip);padding:.1rem .4rem;margin:.1rem .15rem .1rem 0}
.btn--danger{color:var(--danger);background:var(--danger-bg);border-color:var(--danger-line)}
.btn--danger:hover{background:var(--danger-line);color:var(--ink)}
.btn--tiny{width:auto;padding:.32rem .65rem;font-size:.78rem;border-radius:var(--r-chip)}
.btn--auto{width:auto}
.input--compact{width:auto;min-width:8rem;max-width:100%;padding:.42rem .6rem;font-size:.82rem;flex:1 1 9rem}
.panel__head .btn,.toolbar .btn{width:auto}
.form-grid{display:grid;gap:1.1rem;max-width:620px}
.form-grid .field{margin:0}
.form-grid--inline{grid-template-columns:minmax(180px,1fr) minmax(240px,1.5fr) auto;max-width:none;align-items:end}
.form-hint{font-size:.78rem;color:var(--ink-3);margin:.3rem 0 0}
.form-hint--standalone{margin:-.6rem 0 0}
.field-cluster{margin:0;padding:0;border:0;min-width:0}
.field-cluster legend{margin-bottom:.55rem;font-size:.78rem;font-weight:600;color:var(--ink-2)}
.group-choice-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}
.group-choice{display:flex;align-items:flex-start;gap:.6rem;padding:.72rem .8rem;border:1px solid var(--line);border-radius:var(--r-field);background:var(--surface-2);cursor:pointer}
.group-choice:has(input:checked){border-color:var(--brass-line);background:var(--brass-soft)}
.group-choice input{width:auto;margin:.18rem 0 0;accent-color:var(--brass)}
.group-choice span{display:grid;gap:.1rem;min-width:0}
.group-choice b{font-family:var(--font-mono);font-size:.8rem;font-weight:600;color:var(--ink)}
.group-choice small{font-size:.75rem;line-height:1.35;color:var(--ink-3)}
.audit-filters{display:flex;gap:.8rem;flex-wrap:wrap;align-items:flex-end;margin-bottom:1.2rem}
.audit-filters .field{margin:0;flex:1 1 170px}
.audit-filters__actions{display:flex;gap:.5rem;align-items:center}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1.1rem}
.pager{display:flex;gap:.6rem;align-items:center;justify-content:flex-end;margin-top:1.1rem;font-size:.85rem;color:var(--ink-3)}
.secret{margin:.4rem 0 0;padding:.85rem 1rem;font-family:var(--font-mono);font-size:.9rem;word-break:break-all;color:var(--brass-2);background:var(--surface-2);border:1px solid var(--brass-line);border-radius:var(--r-field)}
.checkline{display:flex;align-items:center;gap:.55rem;font-size:.9rem;color:var(--ink)}
.checkline input{width:auto;margin:0}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
.stat{display:flex;flex-direction:column;gap:.4rem;padding:1.3rem 1.4rem;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);box-shadow:var(--shadow)}
.stat:hover{border-color:var(--line-brass);text-decoration:none}
.stat__num{font-size:1.95rem;font-weight:680;letter-spacing:-.02em;color:var(--ink);line-height:1;font-family:var(--font-mono)}
.stat__label{font-size:.84rem;color:var(--ink-2)}
@media (max-width:760px){
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .form-grid--inline,.group-choice-grid{grid-template-columns:1fr}
  .ctable-wrap{overflow:visible}
  .ctable{display:block;min-width:0}
  .ctable thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
  .ctable tbody{display:grid}
  .ctable tr{display:block;padding:.45rem 0;border-bottom:1px solid var(--line)}
  .ctable tbody tr:last-child{border-bottom:0}
  .ctable td{display:grid;width:100%;grid-template-columns:minmax(76px,28%) minmax(0,1fr);gap:.8rem;padding:.55rem 1rem;border:0;align-items:start;overflow-wrap:anywhere}
  .ctable tbody tr:hover td{background:transparent}
  .ctable td::before{content:attr(data-label);font-size:.68rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3)}
  .ctable td[data-label=""]{grid-template-columns:1fr;padding-top:.25rem}
  .ctable td[data-label=""]::before{display:none}
  .ctable td[data-label=""] .ctable__value{grid-column:1}
  .ctable__value{grid-column:2;min-width:0}
  .ctable__value>.actions{justify-content:flex-start;min-width:0}
  .ctable__value>.actions+.actions,.ctable__value>.actions+.form-hint{margin-top:.5rem}
  .ctable__value .input{min-width:0}
}
`

export function renderForbidden(): string {
  const body = `<main class="card">
  <div class="head">${brandHeader()}<h1>Access denied</h1>
  <p class="lead">Your account doesn't have administrator access.</p></div>
  <p class="foot"><a class="link-quiet" href="/">Back to your account</a></p>
</main>`
  return htmlLayout("Access denied — KeyForge", body)
}

function renderFlash(flash: ConsoleFlash | undefined): string {
  if (flash === undefined) {
    return ""
  }
  return `<div class="flash flash--${flash.kind}" role="status">${escapeHtml(flash.message)}</div>`
}

export function consoleShell(title: string, chrome: ConsoleChrome, content: string): string {
  const tabs = TABS.map((tab) => ({
    label: tab.label,
    href: tab.href,
    active: tab.section === chrome.section,
  }))
  const barRight = `<span class="shell-bar__who">Signed in as <b>${escapeHtml(chrome.adminEmail)}</b></span>
      <a class="btn btn--ghost btn--sm" href="/">Your account</a>
      <a class="btn btn--ghost btn--sm" href="/logout">Sign out</a>`
  return appShell({
    title,
    heading: title.replace(/\s+—.*$/, ""),
    badge: "Admin console",
    barRight,
    tabs,
    content: `${renderFlash(chrome.flash)}\n  ${content}`,
    extraStyles: CONSOLE_STYLES,
  })
}
