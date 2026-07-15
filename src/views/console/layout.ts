import { brandHeader, escapeHtml, htmlLayout } from "../layout"

export type ConsoleSection = "overview" | "users" | "clients" | "resources" | "devices" | "audit"

export type ConsoleFlash = { readonly kind: "ok" | "warn"; readonly message: string }

export type ConsoleChrome = {
  readonly section: ConsoleSection
  readonly adminEmail: string
  readonly flash?: ConsoleFlash
}

type NavItem = {
  readonly section: ConsoleSection
  readonly label: string
  readonly href: string
  readonly group: "Workspace" | "Monitor"
  readonly icon: string
}

const icon = (path: string) =>
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="${path}" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`

const NAV: readonly NavItem[] = [
  {
    section: "overview",
    label: "Overview",
    href: "/console",
    group: "Workspace",
    icon: icon("M4 13h6V4H4v9Zm10 7h6V11h-6v9ZM4 20h6v-3H4v3Zm10-13h6V4h-6v3Z"),
  },
  {
    section: "users",
    label: "Users",
    href: "/console/users",
    group: "Workspace",
    icon: icon(
      "M16 20v-1.5A3.5 3.5 0 0 0 12.5 15h-5A3.5 3.5 0 0 0 4 18.5V20m13-9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM10 12a4 4 0 1 0 0-8 4 4 0 0 0 0 0 8Z",
    ),
  },
  {
    section: "clients",
    label: "Applications",
    href: "/console/clients",
    group: "Workspace",
    icon: icon(
      "M5 4h14a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Zm4 16h6m-3-3v3",
    ),
  },
  {
    section: "resources",
    label: "APIs",
    href: "/console/resources",
    group: "Workspace",
    icon: icon("m8 9-4 3 4 3m8-6 4 3-4 3m-5-9-3 12m5-12-3 12"),
  },
  {
    section: "devices",
    label: "Devices",
    href: "/console/devices",
    group: "Workspace",
    icon: icon(
      "M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm2 3h4m-3 12h2",
    ),
  },
  {
    section: "audit",
    label: "Audit log",
    href: "/console/audit",
    group: "Monitor",
    icon: icon(
      "M12 3 4.5 6v5.2c0 4.4 3.1 8.4 7.5 9.8 4.4-1.4 7.5-5.4 7.5-9.8V6L12 3Zm-3 9 2 2 4-4",
    ),
  },
]

const SECTION_COPY: Readonly<Record<ConsoleSection, string>> = {
  overview: "A guided view of your identity service and the next useful setup step.",
  users: "Provision people, organize access groups, and manage their login methods.",
  clients: "Register applications and configure OAuth flows without missing required settings.",
  resources: "Define API audiences and the scopes applications may request.",
  devices: "Review and revoke device authorization sessions.",
  audit: "Trace administrative changes, sign-ins, and OAuth security events.",
}

const CONSOLE_STYLES = `
.stage{display:block;min-height:100vh;padding:0;background:#f7f8fb}.stage::before{display:none}
.console-frame{min-height:100vh;display:grid;grid-template-columns:248px minmax(0,1fr);color:#1f2430;background:#f7f8fb}
.console-sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;padding:1.15rem .9rem;background:#171a24;color:#f5f6f8;border-right:1px solid #242938;overflow-y:auto}
.console-sidebar .brand{flex-direction:row;align-items:center;justify-content:flex-start;gap:.68rem;margin:.1rem .55rem 1.7rem;text-align:left}
.console-sidebar .seal{width:32px;height:32px;color:#f1b96a;filter:none}
.console-sidebar .brand__name{font-size:.95rem;color:#fff;letter-spacing:.1em}
.console-nav{display:grid;gap:1.2rem}
.console-nav__group{display:grid;gap:.28rem}
.console-nav__label{padding:0 .7rem .28rem;color:#787f91;font-size:.65rem;font-weight:700;letter-spacing:.11em;text-transform:uppercase}
.console-nav__link{display:flex;align-items:center;gap:.72rem;padding:.62rem .72rem;border-radius:8px;color:#b9bfca;font-size:.88rem;font-weight:550;transition:background .15s ease,color .15s ease}
.console-nav__link:hover{color:#fff;background:#232735;text-decoration:none}
.console-nav__link--active{color:#fff;background:#2a2e3d;box-shadow:inset 3px 0 #e7b667}
.console-nav__link svg{width:18px;height:18px;flex:none}
.console-sidebar__foot{margin-top:auto;padding:1rem .7rem .3rem;border-top:1px solid #2a2e3b;display:grid;gap:.7rem}
.console-sidebar__who{display:grid;gap:.08rem;min-width:0}.console-sidebar__who span{font-size:.67rem;color:#7f8798;text-transform:uppercase;letter-spacing:.08em}.console-sidebar__who b{font-size:.78rem;color:#dce0e7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.console-sidebar__actions{display:flex;gap:.45rem}.console-sidebar__actions a{color:#aeb5c1;font-size:.75rem}.console-sidebar__actions a:hover{color:#fff}
.console-workspace{min-width:0}
.console-topbar{min-height:74px;display:flex;align-items:center;justify-content:flex-end;padding:.9rem clamp(1.2rem,3vw,2.4rem);background:#fff;border-bottom:1px solid #e6e8ed}
.console-topbar__actions{display:flex;align-items:center;gap:.65rem}.console-topbar .btn{width:auto}
.console-page{width:min(100%,1320px);margin:0 auto;padding:clamp(1.5rem,3vw,2.6rem) clamp(1.2rem,3vw,2.6rem) 4rem}
.console-page__head{display:flex;align-items:flex-start;justify-content:space-between;gap:1.2rem;margin-bottom:1.7rem}
.console-page__head h1{margin:0;color:#202531;font-size:1.72rem;line-height:1.2;font-weight:690;letter-spacing:-.025em;text-align:left}
.console-page__head p{max-width:720px;margin:.42rem 0 0;color:#687080;font-size:.9rem}
.console-content{display:grid;gap:1.15rem}
.flash{display:flex;align-items:center;gap:.6rem;padding:.78rem 1rem;border-radius:9px;font-size:.86rem}
.flash--ok{color:#176c45;background:#eaf7f0;border:1px solid #c8ead8}.flash--warn{color:#a63834;background:#fff0ef;border:1px solid #f0cfcd}
.panel{background:#fff;border:1px solid #e2e5ea;border-radius:12px;box-shadow:0 1px 2px rgba(31,36,48,.04);overflow:hidden;min-width:0}
.panel__head{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding:1.18rem 1.4rem;border-bottom:1px solid #e9ebef}
.panel__title{margin:0;color:#242a36;font-size:1.04rem;font-weight:660;letter-spacing:-.012em}
.panel__desc{margin:.25rem 0 0;color:#727988;font-size:.82rem}
.panel__body{padding:1.35rem 1.4rem}.panel__body>.flash{margin-bottom:1rem}
.ctable-wrap{overflow-x:auto}.ctable{width:100%;min-width:650px;border-collapse:collapse;font-size:.84rem}.ctable th{text-align:left;padding:.68rem 1.35rem;color:#7a8190;background:#fafbfc;border-bottom:1px solid #e7e9ed;font-size:.66rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;white-space:nowrap}.ctable td{padding:.82rem 1.35rem;border-bottom:1px solid #eceef1;vertical-align:middle;color:#333946}.ctable tbody tr:last-child td{border-bottom:0}.ctable tbody tr:hover td{background:#fbfcfd}.ctable .mono{font-family:var(--font-mono);font-size:.8rem;color:#626b7a}.ctable__value{min-width:0;overflow-wrap:anywhere}.ctable__empty{padding:2.6rem 1.4rem;text-align:center;color:#737b89}
.actions{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;justify-content:flex-end}.actions--start{justify-content:flex-start}
.tag{display:inline-block;margin:.1rem .15rem .1rem 0;padding:.1rem .42rem;color:#555e6d;background:#f4f5f7;border:1px solid #e0e3e8;border-radius:6px;font:500 .72rem var(--font-mono)}
.badge{display:inline-flex;align-items:center;gap:.32rem;padding:.16rem .5rem;border-radius:999px;border:1px solid #dfe2e7;color:#626a78;background:#f7f8fa;font-size:.7rem;font-weight:650}.badge--ok{color:#18724a;background:#eaf7f0;border-color:#ccebd9}.badge--warn{color:#96601c;background:#fff7e8;border-color:#f0dfbe}.badge__dot{width:.4rem;height:.4rem;border-radius:50%;background:currentColor}
.btn--danger{color:#b23a36;background:#fff0ef;border-color:#edcfcd}.btn--danger:hover{background:#f9dfdd;color:#9c2925}.btn--tiny{width:auto;padding:.31rem .62rem;font-size:.76rem;border-radius:7px}.btn--auto{width:auto}.btn--primary{color:#211805;border-color:#ca9141;background:#e7b667;box-shadow:none}.btn--primary:hover{background:#edc37f;filter:none;box-shadow:none}.btn--ghost{color:#343a46;background:#fff;border-color:#d9dde4}.btn--ghost:hover{background:#f5f6f8;border-color:#c8cdd6}
.input{color:#252b36;background:#fff;border-color:#cfd4dc;border-radius:8px}.input:hover{border-color:#aab1bd}.input:focus{border-color:#a46e23;box-shadow:0 0 0 3px rgba(164,110,35,.12);background:#fff}.input--compact{width:auto;min-width:8rem;max-width:100%;padding:.42rem .6rem;font-size:.8rem;flex:1 1 9rem}
.panel__head .btn,.toolbar .btn{width:auto}.form-grid{display:grid;gap:1.05rem;max-width:660px}.form-grid .field{margin:0}.form-grid--inline{grid-template-columns:minmax(180px,1fr) minmax(240px,1.5fr) auto;max-width:none;align-items:end}.form-grid--method{max-width:860px;grid-template-columns:repeat(3,minmax(0,1fr)) auto;align-items:end}.form-grid--method .form-hint{grid-column:1/-1}
.form-hint{color:#777f8e;font-size:.76rem;margin:.3rem 0 0}.form-hint--standalone{margin:-.55rem 0 0}.field__label{color:#555d6c;font-size:.76rem;font-weight:650}
.field-cluster{margin:0;padding:0;border:0;min-width:0}.field-cluster legend{margin-bottom:.55rem;color:#555d6c;font-size:.76rem;font-weight:650}
.group-choice-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}.group-choice{display:flex;align-items:flex-start;gap:.6rem;padding:.75rem .8rem;border:1px solid #dfe2e7;border-radius:9px;background:#fafbfc;cursor:pointer}.group-choice:has(input:checked){border-color:#d0a15d;background:#fff8ea}.group-choice input{width:auto;margin:.18rem 0 0;accent-color:#a66f25}.group-choice span{display:grid;gap:.1rem;min-width:0}.group-choice b{color:#303642;font:600 .79rem var(--font-mono)}.group-choice small{color:#777f8d;font-size:.73rem;line-height:1.35}
.resource-choice small{overflow-wrap:anywhere}.resource-choice small.mono{font-size:.68rem}.wizard-empty{padding:1rem;color:#707887;background:#fafbfc;border:1px dashed #d5d9e0;border-radius:9px;font-size:.82rem}.wizard-empty a{color:#8b5d1d}
.audit-filters{display:flex;gap:.8rem;flex-wrap:wrap;align-items:flex-end;margin-bottom:1.2rem}.audit-filters .field{margin:0;flex:1 1 170px}.audit-filters__actions{display:flex;gap:.5rem;align-items:center}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:.15rem}.pager{display:flex;gap:.6rem;align-items:center;justify-content:flex-end;margin-top:1rem;color:#747c8a;font-size:.82rem}.secret{margin:.4rem 0 0;padding:.9rem 1rem;color:#6e4510;background:#fff8e9;border:1px solid #e7cfaa;border-radius:9px;font:500 .86rem var(--font-mono);word-break:break-all}.secret-done{margin-top:1.2rem}.checkline{display:flex;align-items:center;gap:.55rem;color:#363c48;font-size:.86rem}.checkline input{width:auto;margin:0;accent-color:#a66f25}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.8rem}.stat{display:flex;flex-direction:column;gap:.34rem;padding:1.05rem 1.15rem;background:#fff;border:1px solid #e2e5ea;border-radius:10px;box-shadow:0 1px 2px rgba(31,36,48,.03)}.stat:hover{border-color:#d0a15d;text-decoration:none}.stat__num{color:#252b36;font:680 1.65rem/1 var(--font-mono);letter-spacing:-.03em}.stat__label{color:#747c8a;font-size:.78rem}.method-label{display:inline-flex;padding:.2rem .45rem;border-radius:6px;color:#805314;background:#fff5df;border:1px solid #edd7af;font-size:.7rem;font-weight:700}.method-label--passkey{color:#176b49;background:#eaf7f1;border-color:#c9e8d8}
.setup-card{display:grid;grid-template-columns:minmax(240px,.8fr) minmax(0,1.3fr);background:#fff;border:1px solid #e1e4e9;border-radius:14px;overflow:hidden;box-shadow:0 8px 28px -24px rgba(32,37,48,.35)}.setup-card__intro{padding:1.7rem;background:#222633;color:#fff}.setup-card__intro h2{margin:0;font-size:1.28rem;letter-spacing:-.02em}.setup-card__intro p{margin:.55rem 0 1.25rem;color:#b9c0cc;font-size:.84rem}.setup-progress{height:7px;overflow:hidden;background:#363b4a;border-radius:999px}.setup-progress span{display:block;height:100%;background:#e7b667;border-radius:inherit}.setup-card__count{display:block;margin-top:.55rem;color:#aeb5c1;font-size:.72rem}.setup-list{list-style:none;margin:0;padding:0}.setup-step{display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:.8rem;padding:1rem 1.2rem;border-bottom:1px solid #eceef1}.setup-step:last-child{border-bottom:0}.setup-step__mark{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;color:#8a6030;background:#fff6e5;border:1px solid #e9d2aa;font-size:.75rem;font-weight:700}.setup-step--done .setup-step__mark{color:#fff;background:#2e8a60;border-color:#2e8a60}.setup-step h3{margin:0;color:#2b313d;font-size:.88rem}.setup-step p{margin:.18rem 0 0;color:#747c8a;font-size:.75rem}.setup-step .btn{width:auto}
.wizard-shell{display:grid;grid-template-columns:210px minmax(0,1fr);min-height:560px}.wizard-rail{padding:1.4rem 1.1rem;background:#fafbfc;border-right:1px solid #e5e7eb}.wizard-rail h3{margin:0 0 1rem;color:#555d6c;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}.wizard-steps{list-style:none;margin:0;padding:0;display:grid;gap:.3rem}.wizard-step{display:flex;align-items:center;gap:.6rem;padding:.55rem .6rem;border-radius:8px;color:#7a8290;font-size:.8rem}.wizard-step span{display:grid;place-items:center;width:23px;height:23px;border-radius:50%;border:1px solid #cfd4dc;font-size:.68rem;font-weight:700}.wizard-step--active{color:#252b36;background:#fff;border:1px solid #e1e4e9}.wizard-step--active span{color:#241902;background:#e7b667;border-color:#d29b4f}.wizard-step--done span{color:#fff;background:#2f865e;border-color:#2f865e}.wizard-main{padding:1.55rem 1.7rem}.wizard-panel{border:0;padding:0;margin:0;min-width:0}.wizard-panel legend{padding:0;color:#242a36;font-size:1.12rem;font-weight:680}.wizard-panel__lead{margin:.35rem 0 1.4rem;color:#747c8a;font-size:.83rem}.wizard-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}.wizard-grid .field{margin:0}.wizard-grid .field--wide{grid-column:1/-1}.choice-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem;grid-column:1/-1}.choice-cards--two{grid-template-columns:repeat(2,minmax(0,1fr))}.choice-card{position:relative;display:grid;gap:.28rem;padding:1rem;border:1px solid #dfe3e8;border-radius:10px;background:#fff;cursor:pointer}.choice-card:hover{border-color:#c5a26f}.choice-card:has(input:checked){border-color:#ba7e2d;box-shadow:0 0 0 3px rgba(186,126,45,.1);background:#fffbf3}.choice-card input{position:absolute;opacity:0;pointer-events:none}.choice-card b{color:#2b313d;font-size:.86rem}.choice-card small{color:#777f8d;font-size:.73rem;line-height:1.35}.wizard-actions{display:flex;justify-content:space-between;gap:.8rem;margin-top:1.5rem;padding-top:1.1rem;border-top:1px solid #eceef1}.wizard-actions__right{display:flex;gap:.55rem}.wizard-actions .btn{width:auto}.wizard-review{display:grid;gap:1px;background:#e6e8ec;border:1px solid #e3e5e9;border-radius:9px;overflow:hidden}.wizard-review__row{display:grid;grid-template-columns:150px minmax(0,1fr);gap:1rem;padding:.72rem .85rem;background:#fff}.wizard-review__row dt{color:#777f8e;font-size:.76rem}.wizard-review__row dd{margin:0;color:#313743;font:500 .78rem var(--font-mono);white-space:pre-wrap;overflow-wrap:anywhere}
[data-console-wizard][data-wizard-ready] [data-wizard-step]:not(.wizard-panel--active){display:none}
@media (prefers-color-scheme:dark){.stage,.console-frame{background:#0f1117}.console-workspace{color:#e9ebef}.console-topbar,.panel,.stat,.setup-card,.wizard-step--active,.choice-card,.wizard-review__row{background:#171a22;border-color:#2a2e39}.console-page__head h1,.panel__title,.ctable td,.stat__num,.setup-step h3,.wizard-panel legend,.choice-card b,.wizard-review__row dd{color:#eceef2}.console-page__head p,.panel__desc,.form-hint,.stat__label,.setup-step p,.wizard-panel__lead,.choice-card small,.wizard-review__row dt{color:#9ca3b0}.console-topbar{border-color:#292d37}.panel__head,.ctable th,.ctable td,.setup-step,.wizard-actions{border-color:#292d37}.ctable th,.ctable tbody tr:hover td,.wizard-rail{background:#13161d}.input{color:#edf0f4;background:#11141a;border-color:#383d49}.input:focus{background:#11141a}.btn--ghost{color:#e1e4e9;background:#1d2029;border-color:#383d49}.tag,.badge{color:#bac0ca;background:#20232c;border-color:#363a45}.group-choice{background:#151820;border-color:#333844}.group-choice b{color:#e4e7eb}.setup-card__intro{background:#20232d}.setup-step__mark{background:#2c261d}.wizard-step--active{background:#20232b}.choice-card:has(input:checked){background:#272116}.wizard-review{background:#2a2e38;border-color:#2a2e38}}
@media(max-width:900px){.console-frame{grid-template-columns:1fr}.console-sidebar{position:relative;height:auto;padding:.75rem}.console-sidebar .brand{margin:.1rem .45rem .8rem}.console-nav{display:flex;gap:.35rem;overflow-x:auto}.console-nav__group{display:flex;gap:.25rem}.console-nav__label,.console-sidebar__foot{display:none}.console-nav__link{white-space:nowrap;padding:.52rem .62rem}.console-nav__link--active{box-shadow:inset 0 -2px #e7b667}.console-topbar{display:none}.console-page{padding-top:1.35rem}.setup-card{grid-template-columns:1fr}.wizard-shell{grid-template-columns:1fr}.wizard-rail{border-right:0;border-bottom:1px solid #e5e7eb}.wizard-steps{grid-template-columns:repeat(4,minmax(0,1fr))}.wizard-step{padding:.45rem}.wizard-step strong{display:none}}
@media(max-width:720px){.stat-grid{grid-template-columns:repeat(2,1fr)}.form-grid--inline,.form-grid--method,.group-choice-grid,.wizard-grid,.choice-cards{grid-template-columns:1fr}.wizard-grid .field--wide{grid-column:auto}.ctable-wrap{overflow:visible}.ctable{display:block;min-width:0}.ctable thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.ctable tbody{display:grid}.ctable tr{display:block;padding:.4rem 0;border-bottom:1px solid #e6e8ed}.ctable tbody tr:last-child{border-bottom:0}.ctable td{display:grid;width:100%;grid-template-columns:minmax(82px,30%) minmax(0,1fr);gap:.7rem;padding:.5rem 1rem;border:0;align-items:start;overflow-wrap:anywhere}.ctable tbody tr:hover td{background:transparent}.ctable td::before{content:attr(data-label);color:#7a8190;font-size:.65rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase}.ctable td[data-label=""]{grid-template-columns:1fr}.ctable td[data-label=""]::before{display:none}.ctable__value{grid-column:2}.ctable td[data-label=""] .ctable__value{grid-column:1}.ctable__value>.actions{justify-content:flex-start}.setup-step{grid-template-columns:30px minmax(0,1fr)}.setup-step .btn{grid-column:2}.wizard-main{padding:1.2rem}.wizard-review__row{grid-template-columns:1fr;gap:.2rem}}
`

export function renderForbidden(): string {
  const body = `<main class="card"><div class="head">${brandHeader()}<h1>Access denied</h1><p class="lead">Your account doesn't have administrator access.</p></div><p class="foot"><a class="link-quiet" href="/">Back to your account</a></p></main>`
  return htmlLayout("Access denied — KeyForge", body)
}

function renderFlash(flash: ConsoleFlash | undefined): string {
  return flash === undefined
    ? ""
    : `<div class="flash flash--${flash.kind}" role="status">${escapeHtml(flash.message)}</div>`
}

function navGroups(active: ConsoleSection): string {
  return (["Workspace", "Monitor"] as const)
    .map((group) => {
      const links = NAV.filter((item) => item.group === group)
        .map((item) => {
          const selected = item.section === active
          return `<a class="console-nav__link${selected ? " console-nav__link--active" : ""}" href="${item.href}"${selected ? ' aria-current="page"' : ""}>${item.icon}<span>${escapeHtml(item.label)}</span></a>`
        })
        .join("")
      return `<div class="console-nav__group"><div class="console-nav__label">${group}</div>${links}</div>`
    })
    .join("")
}

export function consoleShell(title: string, chrome: ConsoleChrome, content: string): string {
  const heading = title.replace(/\s+—.*$/, "")
  const body = `<div class="console-frame">
  <aside class="console-sidebar">${brandHeader()}<nav class="console-nav" aria-label="Admin console">${navGroups(chrome.section)}</nav><div class="console-sidebar__foot"><div class="console-sidebar__who"><span>Signed in as</span><b>${escapeHtml(chrome.adminEmail)}</b></div><div class="console-sidebar__actions"><a href="/">Your account</a><a href="/logout">Sign out</a></div></div></aside>
  <div class="console-workspace"><header class="console-topbar"><div class="console-topbar__actions"><a class="btn btn--ghost btn--sm" href="/">Your account</a><a class="btn btn--ghost btn--sm" href="/logout">Sign out</a></div></header><main class="console-page console-main shell-main"><div class="console-page__head"><div><h1>${escapeHtml(heading)}</h1><p>${escapeHtml(SECTION_COPY[chrome.section])}</p></div></div><div class="console-content">${renderFlash(chrome.flash)}${content}</div></main></div>
  <script src="/assets/console.js" defer></script>
</div>`
  return htmlLayout(title, body, CONSOLE_STYLES)
}
