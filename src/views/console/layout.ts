import type { I18n } from "../../i18n"
import { appShell, brandHeader, escapeHtml, htmlLayout } from "../layout"

export type ConsoleSection = "overview" | "users" | "clients" | "resources" | "devices" | "audit"

export type ConsoleFlash = { readonly kind: "ok" | "warn"; readonly message: string }

export type ConsoleChrome = {
  readonly i18n: I18n
  readonly section: ConsoleSection
  readonly adminEmail: string
  readonly flash?: ConsoleFlash
}

const NAV: readonly {
  readonly section: ConsoleSection
  readonly label: string
  readonly href: string
}[] = [
  { section: "overview", label: "Overview", href: "/console" },
  { section: "users", label: "Users", href: "/console/users" },
  { section: "clients", label: "Applications", href: "/console/clients" },
  { section: "resources", label: "APIs", href: "/console/resources" },
  { section: "devices", label: "Devices", href: "/console/devices" },
  { section: "audit", label: "Audit log", href: "/console/audit" },
]

const SECTION_COPY: Readonly<Record<ConsoleSection, string>> = {
  overview: "A guided view of your identity service and the next useful setup step.",
  users: "Provision people, organize access groups, and manage their login methods.",
  clients: "Register applications and configure OAuth flows without missing required settings.",
  resources: "Define API audiences and the scopes applications may request.",
  devices: "Review and revoke device authorization sessions.",
  audit: "Trace administrative changes, sign-ins, and OAuth security events.",
}

/**
 * Console-specific composition only. Colors, surfaces, radii, controls, and
 * typography all come from the shared KeyForge design system in layout.ts.
 */
const CONSOLE_STYLES = `
html{scrollbar-gutter:stable}
.console-content{display:grid;gap:1.4rem;min-width:0}
.flash{display:flex;align-items:center;gap:.6rem;padding:.75rem 1rem;border-radius:var(--r-field);font-size:.9rem}
.flash--ok{color:var(--ok);background:var(--ok-soft);border:1px solid transparent}
.flash--warn{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line)}

.panel{position:relative;min-width:0;overflow:hidden;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);box-shadow:var(--shadow);animation:rise .5s cubic-bezier(.2,.7,.2,1) both}
.panel::before,.setup-card::before,.stat::before{content:"";position:absolute;z-index:1;top:0;left:1px;right:1px;height:1px;background:linear-gradient(90deg,transparent,var(--brass-line),transparent)}
.panel__head{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding:1.25rem 1.5rem;border-bottom:1px solid var(--line)}
.panel__title{margin:0;color:var(--ink);font-size:1.08rem;font-weight:640;letter-spacing:-.01em}
.panel__desc{margin:.2rem 0 0;color:var(--ink-2);font-size:.85rem}
.panel__body{padding:1.4rem 1.5rem}
.panel__body>.flash{margin-bottom:1rem}

.ctable-wrap{min-width:0;overflow-x:auto}
.ctable{width:100%;min-width:620px;border-collapse:collapse;font-size:.87rem}
.ctable th{text-align:left;padding:.7rem 1.5rem;color:var(--ink-3);background:var(--surface-2);border-bottom:1px solid var(--line);font-size:.7rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}
.ctable td{padding:.85rem 1.5rem;border-bottom:1px solid var(--line);vertical-align:middle;color:var(--ink)}
.ctable tbody tr:last-child td{border-bottom:0}
.ctable tbody tr:hover td{background:var(--surface-2)}
.ctable .mono{font-family:var(--font-mono);font-size:.82rem;color:var(--ink-2)}
.ctable__value{min-width:0;overflow-wrap:anywhere}
.ctable__empty{padding:2.5rem 1.5rem;text-align:center;color:var(--ink-2)}

.actions{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;justify-content:flex-end}
.actions--start{justify-content:flex-start}
.tag{display:inline-block;margin:.1rem .15rem .1rem 0;padding:.1rem .4rem;color:var(--ink-2);background:var(--surface-3);border:1px solid var(--line-2);border-radius:var(--r-chip);font:500 .74rem var(--font-mono)}
.btn--tiny{width:auto;padding:.32rem .65rem;font-size:.78rem;border-radius:var(--r-chip)}
.btn--auto{width:auto}
.input--compact{width:auto;min-width:8rem;max-width:100%;padding:.42rem .6rem;font-size:.82rem;flex:1 1 9rem}
.panel__head .btn,.toolbar .btn{width:auto}

.form-grid{display:grid;gap:1.1rem;max-width:620px}
.form-grid .field{margin:0}
.form-grid--inline{grid-template-columns:minmax(180px,1fr) minmax(240px,1.5fr) auto;max-width:none;align-items:end}
.form-grid--method{max-width:860px;grid-template-columns:repeat(3,minmax(0,1fr)) auto;align-items:end}
.form-grid--method .form-hint{grid-column:1/-1}
.form-hint{margin:.3rem 0 0;color:var(--ink-3);font-size:.78rem}
.form-hint--standalone{margin:-.6rem 0 0}
.username-impact{display:grid;gap:.18rem;margin:0;padding:.78rem .9rem;font-size:.82rem}
.username-impact strong{color:var(--brass-2);font-size:.84rem}
.username-impact span{color:var(--ink-2)}
.field-cluster{margin:0;padding:0;border:0;min-width:0}
.field-cluster legend{margin-bottom:.55rem;color:var(--ink-2);font-size:.78rem;font-weight:600}
.group-choice-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}
.group-choice{display:flex;align-items:flex-start;gap:.6rem;padding:.72rem .8rem;border:1px solid var(--line);border-radius:var(--r-field);background:var(--surface-2);cursor:pointer;transition:border-color .16s ease,background .16s ease,box-shadow .16s ease}
.group-choice:hover{border-color:var(--line-brass)}
.group-choice:has(input:checked){border-color:var(--brass-line);background:var(--brass-soft);box-shadow:var(--focus)}
.group-choice input{width:auto;margin:.18rem 0 0;accent-color:var(--brass)}
.group-choice span{display:grid;gap:.1rem;min-width:0}
.group-choice b{color:var(--ink);font:600 .8rem var(--font-mono)}
.group-choice small{color:var(--ink-3);font-size:.75rem;line-height:1.35}
.resource-choice small{overflow-wrap:anywhere}
.resource-choice small.mono{font-size:.68rem}
.wizard-empty{padding:1rem;color:var(--ink-2);background:var(--surface-2);border:1px dashed var(--line-2);border-radius:var(--r-field);font-size:.84rem}

.audit-filters{display:flex;gap:.8rem;flex-wrap:wrap;align-items:flex-end;margin-bottom:1.2rem}
.audit-filters .field{margin:0;flex:1 1 170px}
.audit-filters__actions{display:flex;gap:.5rem;align-items:center}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.pager{display:flex;gap:.6rem;align-items:center;justify-content:flex-end;margin-top:1.1rem;color:var(--ink-3);font-size:.85rem}
.secret{margin:.4rem 0 0;padding:.85rem 1rem;color:var(--brass-2);background:var(--surface-2);border:1px solid var(--brass-line);border-radius:var(--r-field);font:500 .9rem var(--font-mono);word-break:break-all}
.secret-done{margin-top:1.2rem}
.checkline{display:flex;align-items:center;gap:.55rem;color:var(--ink);font-size:.9rem}
.checkline input{width:auto;margin:0;accent-color:var(--brass)}
.method-label{display:inline-flex;padding:.16rem .45rem;border-radius:var(--r-pill);color:var(--brass);background:var(--brass-soft);border:1px solid transparent;font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.method-label--passkey{color:var(--ok);background:var(--ok-soft)}

.stat-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem}
.stat{position:relative;display:flex;min-width:0;flex-direction:column;gap:.4rem;padding:1.3rem 1.4rem;overflow:hidden;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);box-shadow:var(--shadow);transition:border-color .16s ease,transform .16s ease}
.stat:hover{border-color:var(--line-brass);text-decoration:none;transform:translateY(-1px)}
.stat__num{color:var(--ink);font:680 1.95rem/1 var(--font-mono);letter-spacing:-.02em}
.stat__label{color:var(--ink-2);font-size:.84rem}

.setup-card{position:relative;display:grid;grid-template-columns:minmax(240px,.82fr) minmax(0,1.35fr);overflow:hidden;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);box-shadow:var(--shadow)}
.setup-card__intro{padding:1.7rem;background:var(--surface-2);border-right:1px solid var(--line)}
.setup-card__intro h2{margin:0;color:var(--ink);font-size:1.22rem;font-weight:640;letter-spacing:-.014em}
.setup-card__intro p{margin:.55rem 0 1.25rem;color:var(--ink-2);font-size:.86rem}
.setup-progress{height:7px;overflow:hidden;background:var(--surface-3);border-radius:var(--r-pill)}
.setup-progress span{display:block;height:100%;background:linear-gradient(90deg,var(--brass),var(--brass-2));border-radius:inherit}
.setup-card__count{display:block;margin-top:.55rem;color:var(--ink-3);font-size:.74rem}
.setup-list{list-style:none;margin:0;padding:0}
.setup-step{display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:.8rem;padding:1rem 1.2rem;border-bottom:1px solid var(--line)}
.setup-step:last-child{border-bottom:0}
.setup-step__mark{display:grid;place-items:center;width:28px;height:28px;border-radius:var(--r-pill);color:var(--brass);background:var(--brass-soft);border:1px solid var(--brass-line);font-size:.75rem;font-weight:700}
.setup-step--done .setup-step__mark{color:var(--surface);background:var(--ok);border-color:var(--ok)}
.setup-step h3{margin:0;color:var(--ink);font-size:.9rem;font-weight:600}
.setup-step p{margin:.18rem 0 0;color:var(--ink-2);font-size:.77rem}
.setup-step .btn{width:auto}

.wizard-shell{display:grid;grid-template-columns:210px minmax(0,1fr);min-height:560px}
.wizard-rail{padding:1.4rem 1.1rem;background:var(--surface-2);border-right:1px solid var(--line)}
.wizard-rail h3{margin:0 0 1rem;color:var(--ink-3);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
.wizard-steps{list-style:none;margin:0;padding:0;display:grid;gap:.3rem}
.wizard-step{display:flex;align-items:center;gap:.6rem;padding:.55rem .6rem;border:1px solid transparent;border-radius:var(--r-chip);color:var(--ink-3);font-size:.8rem}
.wizard-step span{display:grid;place-items:center;width:23px;height:23px;border-radius:var(--r-pill);border:1px solid var(--line-2);font-size:.68rem;font-weight:700}
.wizard-step--active{color:var(--ink);background:var(--surface);border-color:var(--line)}
.wizard-step--active span{color:var(--brass-ink);background:linear-gradient(180deg,var(--brass-2),var(--brass));border-color:var(--brass-2)}
.wizard-step--done span{color:var(--surface);background:var(--ok);border-color:var(--ok)}
.wizard-main{min-width:0;padding:1.55rem 1.7rem}
.wizard-panel{border:0;padding:0;margin:0;min-width:0}
.wizard-panel legend{padding:0;color:var(--ink);font-size:1.12rem;font-weight:640}
.wizard-panel__lead{margin:.35rem 0 1.4rem;color:var(--ink-2);font-size:.84rem}
.wizard-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
.wizard-grid .field{margin:0}
.wizard-grid .field--wide{grid-column:1/-1}
.choice-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem;grid-column:1/-1}
.choice-cards--two{grid-template-columns:repeat(2,minmax(0,1fr))}
.choice-card{position:relative;display:grid;gap:.28rem;padding:1rem;border:1px solid var(--line);border-radius:var(--r-field);background:var(--surface-2);cursor:pointer;transition:border-color .16s ease,background .16s ease,box-shadow .16s ease}
.choice-card:hover{border-color:var(--line-brass)}
.choice-card:has(input:checked){border-color:var(--brass-line);box-shadow:var(--focus);background:var(--brass-soft)}
.choice-card input{position:absolute;opacity:0;pointer-events:none}
.choice-card b{color:var(--ink);font-size:.86rem}
.choice-card small{color:var(--ink-3);font-size:.74rem;line-height:1.35}
.wizard-actions{display:flex;justify-content:space-between;gap:.8rem;margin-top:1.5rem;padding-top:1.1rem;border-top:1px solid var(--line)}
.wizard-actions__right{display:flex;gap:.55rem}
.wizard-actions .btn{width:auto}
.wizard-review{display:grid;gap:1px;overflow:hidden;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field)}
.wizard-review__row{display:grid;grid-template-columns:150px minmax(0,1fr);gap:1rem;padding:.72rem .85rem;background:var(--surface)}
.wizard-review__row dt{color:var(--ink-3);font-size:.76rem}
.wizard-review__row dd{margin:0;color:var(--ink);font:500 .78rem var(--font-mono);white-space:pre-wrap;overflow-wrap:anywhere}
[data-console-wizard][data-wizard-ready] [data-wizard-step]:not(.wizard-panel--active){display:none}

@media(max-width:900px){
  .setup-card{grid-template-columns:1fr}
  .setup-card__intro{border-right:0;border-bottom:1px solid var(--line)}
  .wizard-shell{grid-template-columns:1fr;min-height:0}
  .wizard-rail{border-right:0;border-bottom:1px solid var(--line)}
  .wizard-steps{grid-template-columns:repeat(4,minmax(0,1fr))}
  .wizard-step{justify-content:center;padding:.45rem}
  .wizard-step strong{display:none}
}
@media(max-width:720px){
  .stat-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .form-grid--inline,.form-grid--method,.group-choice-grid,.wizard-grid,.choice-cards{grid-template-columns:1fr}
  .wizard-grid .field--wide{grid-column:auto}
  .ctable-wrap{overflow:visible}
  .ctable{display:block;min-width:0}
  .ctable thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
  .ctable tbody{display:grid}
  .ctable tr{display:block;padding:.45rem 0;border-bottom:1px solid var(--line)}
  .ctable tbody tr:last-child{border-bottom:0}
  .ctable td{display:grid;width:100%;grid-template-columns:minmax(82px,30%) minmax(0,1fr);gap:.7rem;padding:.5rem 1rem;border:0;align-items:start;overflow-wrap:anywhere}
  .ctable tbody tr:hover td{background:transparent}
  .ctable td::before{content:attr(data-label);color:var(--ink-3);font-size:.66rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
  .ctable td[data-label=""]{grid-template-columns:1fr}
  .ctable td[data-label=""]::before{display:none}
  .ctable__value{grid-column:2}
  .ctable td[data-label=""] .ctable__value{grid-column:1}
  .ctable__value>.actions{justify-content:flex-start}
  .setup-step{grid-template-columns:30px minmax(0,1fr)}
  .setup-step .btn{grid-column:2}
  .wizard-main{padding:1.2rem}
  .wizard-review__row{grid-template-columns:1fr;gap:.2rem}
}
@media(max-width:480px){
  .stat-grid{grid-template-columns:1fr}
  .panel__head,.panel__body{padding-left:1.1rem;padding-right:1.1rem}
  .wizard-actions{align-items:stretch;flex-direction:column}
  .wizard-actions__right{display:grid}
  .wizard-actions .btn{width:100%}
}
`

export function renderForbidden(i18n: I18n): string {
  const body = `<main class="card"><div class="head">${brandHeader()}<h1>${escapeHtml(i18n.t("Access denied"))}</h1><p class="lead">${escapeHtml(i18n.t("Your account doesn't have administrator access."))}</p></div><p class="foot"><a class="link-quiet" href="/">${escapeHtml(i18n.t("Back to your account"))}</a></p></main>`
  return htmlLayout(i18n, i18n.t("Access denied — KeyForge"), body)
}

function renderFlash(i18n: I18n, flash: ConsoleFlash | undefined): string {
  return flash === undefined
    ? ""
    : `<div class="flash flash--${flash.kind}" role="status">${escapeHtml(i18n.t(flash.message))}</div>`
}

export function consoleShell(heading: string, chrome: ConsoleChrome, content: string): string {
  const { i18n } = chrome
  const pageTitle = `${heading} — ${i18n.t("Admin console")}`
  const tabs = NAV.map((item) => ({
    label: i18n.t(item.label),
    href: item.href,
    active: item.section === chrome.section,
  }))
  const barRight = `<span class="shell-bar__who">${escapeHtml(i18n.t("Signed in as"))} <b>${escapeHtml(chrome.adminEmail)}</b></span><a class="btn btn--ghost btn--sm" href="/">${escapeHtml(i18n.t("Your account"))}</a><a class="btn btn--ghost btn--sm" href="/logout">${escapeHtml(i18n.t("Sign out"))}</a>`
  return appShell({
    i18n,
    title: pageTitle,
    heading,
    headingDescription: i18n.t(SECTION_COPY[chrome.section]),
    badge: i18n.t("Admin console"),
    barRight,
    tabs,
    content: `<div class="console-content">${renderFlash(i18n, chrome.flash)}${content}</div><script src="/assets/console.js" defer></script>`,
    extraStyles: CONSOLE_STYLES,
  })
}
