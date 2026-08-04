import type { I18n } from "../i18n"
import { avatarPath } from "../media/avatar"
import type { User } from "../types/domain"

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

/**
 * Design system — "the secure threshold".
 *
 * Identity: forged brass on tempered graphite. A calm, engineered aesthetic for
 * an identity provider — trust through precision and restraint rather than
 * decoration. The one signature element is the concentric keyhole seal; every
 * other surface stays quiet. Technical values (codes, scopes, ids) are set in a
 * monospace utility face because they *are* machine values. A light
 * "official-document" theme mirrors the dark one via prefers-color-scheme.
 */
const BASE_STYLES = `
:root{
  color-scheme:dark light;
  --bg:#0a0b0f; --bg-glow:rgba(231,182,103,.10);
  --surface:#14161f; --surface-2:#1b1e29; --surface-3:#232734;
  --line:#262a36; --line-2:#333846; --line-brass:rgba(231,182,103,.30);
  --ink:#edeef2; --ink-2:#a4a9b6; --ink-3:#8b91a1;
  --brass:#e7b667; --brass-2:#f3d197; --brass-ink:#1c1608;
  --brass-soft:rgba(231,182,103,.12); --brass-line:rgba(231,182,103,.45);
  --ok:#79d3a5; --ok-soft:rgba(121,211,165,.12);
  --danger:#f2908b; --danger-bg:#26161a; --danger-soft:rgba(242,144,139,.12); --danger-line:#50292e;
  --font-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --font-mono:ui-monospace,"SF Mono",SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace;
  --r-card:20px; --r-field:11px; --r-chip:8px; --r-pill:999px;
  --shadow:0 1px 0 rgba(255,255,255,.04) inset,0 24px 60px -28px rgba(0,0,0,.7),0 10px 24px -18px rgba(0,0,0,.6);
  --focus:0 0 0 3px var(--brass-soft),0 0 0 1px var(--brass-line);
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#f3f1ea; --bg-glow:rgba(154,106,30,.10);
    --surface:#fffefb; --surface-2:#f6f3ec; --surface-3:#eee9dd;
    --line:#e5e0d3; --line-2:#d6d0bf; --line-brass:rgba(154,106,30,.28);
    --ink:#211d16; --ink-2:#5d574a; --ink-3:#6c665a;
    --brass:#9a6a1e; --brass-2:#b3822c; --brass-ink:#fffdf6;
    --brass-soft:rgba(154,106,30,.10); --brass-line:rgba(154,106,30,.40);
    --ok:#2f7d54; --ok-soft:rgba(47,125,84,.12);
    --danger:#b23a36; --danger-bg:#fbeceb; --danger-soft:rgba(178,58,54,.10); --danger-line:#eccbc9;
    --shadow:0 1px 0 rgba(255,255,255,.7) inset,0 24px 50px -30px rgba(60,45,15,.35),0 8px 20px -16px rgba(60,45,15,.25);
  }
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;min-height:100vh;min-height:100dvh;color:var(--ink);
  font:400 16px/1.55 var(--font-sans);
  background:var(--bg);
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.language-picker{
  display:inline-flex;align-items:center;gap:.35rem;min-width:0;padding:.25rem .38rem;
  color:var(--ink-3);border:1px solid transparent;border-radius:var(--r-chip);
  transition:color .16s ease,background .16s ease,border-color .16s ease,box-shadow .16s ease;
}
.language-picker:hover{color:var(--ink);background:var(--surface-2);border-color:var(--line)}
.language-picker:focus-within{color:var(--ink);background:var(--surface);border-color:var(--brass-line);box-shadow:var(--focus)}
.language-picker__icon{flex:none;width:15px;height:15px}
.language-picker__field{position:relative;display:flex;align-items:center;min-width:0}
.language-picker__field::after{
  content:"";position:absolute;right:.42rem;top:50%;width:.34rem;height:.34rem;pointer-events:none;
  border-right:1.5px solid currentColor;border-bottom:1.5px solid currentColor;transform:translateY(-70%) rotate(45deg);
}
.language-picker__select{
  max-width:10.5rem;min-width:0;padding:.2rem 1.35rem .2rem .15rem;
  color:inherit;background:transparent;border:0;outline:0;appearance:none;cursor:pointer;
  font:550 .78rem/1.4 var(--font-sans);
}
.language-picker__select option{color:var(--ink);background:var(--surface)}
.language-picker__apply{width:auto;padding:.3rem .55rem;font-size:.76rem}
.language-picker--card{margin-top:.1rem;background:color-mix(in srgb,var(--bg) 38%,transparent)}
.language-picker--shell{flex:none;color:var(--ink-2);background:var(--surface-2);border-color:var(--line)}
.stage-stack{position:relative;width:100%;display:flex;flex-direction:column;align-items:center;gap:.65rem}
/* Signature backdrop: a soft forge glow over a faint guilloché ring field. */
.stage{
  position:relative;min-height:100vh;min-height:100dvh;
  display:grid;grid-template-columns:minmax(0,1fr);place-items:center;padding:clamp(1rem,4vw,2.75rem);
  background:
    radial-gradient(120% 90% at 50% -8%,var(--bg-glow),transparent 55%),
    repeating-radial-gradient(circle at 50% 42%,transparent 0 26px,var(--line-brass) 26px 26.6px);
  background-blend-mode:normal;
}
@media (prefers-color-scheme: light){.stage{background:
  radial-gradient(120% 90% at 50% -8%,var(--bg-glow),transparent 55%),
  repeating-radial-gradient(circle at 50% 42%,transparent 0 26px,var(--line-brass) 26px 26.6px);}}
.stage::before{
  content:"";position:absolute;inset:0;pointer-events:none;
  -webkit-mask-image:radial-gradient(70% 55% at 50% 42%,#000,transparent 75%);
  mask-image:radial-gradient(70% 55% at 50% 42%,#000,transparent 75%);
  opacity:.5;
}

/* Card + wide (account) variant */
.card{
  position:relative;width:min(100%,400px);
  background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);
  padding:clamp(1.5rem,5vw,2.25rem);box-shadow:var(--shadow);
  animation:rise .5s cubic-bezier(.2,.7,.2,1) both;
}
.card--wide{width:min(100%,480px)}
/* Stamped seal-band across the card top */
.card::before{
  content:"";position:absolute;left:1px;right:1px;top:0;height:1px;border-radius:var(--r-card) var(--r-card) 0 0;
  background:linear-gradient(90deg,transparent,var(--brass-line),transparent);
}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* Brand lockup */
.brand{display:flex;flex-direction:column;align-items:center;gap:.6rem;text-align:center;margin-bottom:1.6rem}
.seal{position:relative;color:var(--brass);width:48px;height:48px;filter:drop-shadow(0 3px 10px var(--brass-soft))}
.seal svg{display:block;width:100%;height:100%}
.brand__name{font-size:1.02rem;font-weight:650;letter-spacing:.14em;text-transform:uppercase}

/* Typography */
h1{margin:0;font-size:1.42rem;line-height:1.25;font-weight:640;letter-spacing:-.014em;text-align:center}
.lead{margin:.55rem 0 0;color:var(--ink-2);font-size:.92rem;text-align:center}
.eyebrow{margin:0 0 .55rem;font-size:.7rem;font-weight:600;letter-spacing:.15em;text-transform:uppercase;color:var(--ink-3);text-align:center}
.mono{font-family:var(--font-mono);font-size:.86em;letter-spacing:.01em}
strong{font-weight:640;color:var(--ink)}

/* Header block spacing inside a card */
.head{margin-bottom:1.4rem}

/* Form */
form{margin:0}
.field{display:block;margin:0 0 1rem}
.field__label{display:block;margin:0 0 .4rem;font-size:.8rem;font-weight:550;color:var(--ink-2)}
.input{
  width:100%;padding:.72rem .85rem;font:inherit;font-size:.96rem;color:var(--ink);
  background:var(--surface-2);border:1px solid var(--line-2);border-radius:var(--r-field);
  transition:border-color .16s ease,box-shadow .16s ease,background .16s ease;
}
.input::placeholder{color:var(--ink-3)}
.input:hover{border-color:var(--line-brass)}
.input:focus{outline:none;border-color:var(--brass-line);box-shadow:var(--focus);background:var(--surface)}
.input--code{
  font-family:var(--font-mono);font-size:1.28rem;letter-spacing:.32em;text-align:center;
  text-transform:uppercase;padding:.85rem .5rem;
}

/* Buttons */
.btn{
  position:relative;display:inline-flex;align-items:center;justify-content:center;gap:.5rem;
  width:100%;padding:.78rem 1rem;font:inherit;font-size:.95rem;font-weight:600;
  border:1px solid transparent;border-radius:var(--r-field);cursor:pointer;
  transition:transform .12s ease,background .16s ease,border-color .16s ease,box-shadow .16s ease,color .16s ease;
  -webkit-user-select:none;user-select:none;
}
.btn:focus-visible{outline:none;box-shadow:var(--focus)}
.btn:active{transform:translateY(1px)}
.btn--primary{
  color:var(--brass-ink);border-color:var(--brass-2);
  background:linear-gradient(180deg,var(--brass-2),var(--brass));
  box-shadow:0 1px 0 rgba(255,255,255,.25) inset,0 8px 20px -12px var(--brass-soft);
}
.btn--primary:hover{filter:brightness(1.04);box-shadow:0 1px 0 rgba(255,255,255,.3) inset,0 10px 26px -12px var(--brass-line)}
.btn--ghost{color:var(--ink);background:var(--surface-2);border-color:var(--line-2)}
.btn--ghost:hover{background:var(--surface-3);border-color:var(--line-brass)}
.btn--danger{color:var(--danger);background:var(--danger-bg);border-color:var(--danger-line)}
.btn--danger:hover{filter:brightness(1.03);border-color:var(--danger)}
.btn[disabled]{opacity:.55;cursor:not-allowed;transform:none}
.btn.is-loading{color:transparent;pointer-events:none}
.btn.is-loading::after{
  content:"";position:absolute;width:1.05em;height:1.05em;border-radius:50%;
  border:2px solid currentColor;border-top-color:transparent;
  color:var(--brass-ink);animation:spin .6s linear infinite;
}
.btn--ghost.is-loading::after{color:var(--ink-2)}
@keyframes spin{to{transform:rotate(360deg)}}
.btn-row{display:flex;gap:.65rem;margin-top:.2rem}
.btn-row .btn{width:auto;flex:1}

/* Alerts */
.alert{
  display:flex;gap:.6rem;align-items:flex-start;margin:0 0 1.1rem;padding:.7rem .85rem;
  font-size:.86rem;line-height:1.45;border-radius:var(--r-chip);
  color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line);
}
.alert__icon{flex:none;margin-top:.05rem;opacity:.9}
.alert strong{color:var(--danger)}

/* Meta / account rows */
.meta{display:grid;gap:1px;margin:1.4rem 0 0;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field);overflow:hidden}
.meta__row{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.8rem .95rem;background:var(--surface)}
.meta__key{font-size:.82rem;color:var(--ink-3)}
.meta__val{font-size:.88rem;color:var(--ink);text-align:right;overflow-wrap:anywhere}

/* Account identity block */
.identity{display:flex;align-items:center;gap:.9rem;margin:1.5rem 0 0;padding:.9rem;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-field)}
.avatar{flex:none;width:44px;height:44px;border-radius:var(--r-pill);object-fit:cover;border:1px solid var(--line-brass);background:var(--surface-3)}
.avatar--fallback{display:grid;place-items:center;color:var(--brass);font-weight:640;font-size:1.05rem;letter-spacing:.02em}
.identity__body{min-width:0}
.identity__name{font-weight:600;font-size:.98rem;overflow-wrap:anywhere}
.identity__sub{font-size:.85rem;color:var(--ink-2);overflow-wrap:anywhere}

/* Badges */
.badge{display:inline-flex;align-items:center;gap:.32rem;padding:.16rem .5rem;font-size:.72rem;font-weight:600;letter-spacing:.02em;border-radius:var(--r-pill);border:1px solid var(--line-2);color:var(--ink-2);background:var(--surface-3)}
.badge--ok{color:var(--ok);background:var(--ok-soft);border-color:transparent}
.badge--warn{color:var(--brass);background:var(--brass-soft);border-color:transparent}
.badge__dot{width:.42rem;height:.42rem;border-radius:50%;background:currentColor}

/* Permission / scope list */
.perm{list-style:none;margin:1.15rem 0 1.3rem;padding:0;display:grid;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--r-field);overflow:hidden}
.perm li{display:flex;align-items:flex-start;gap:.65rem;padding:.72rem .9rem;background:var(--surface);font-size:.9rem}
.perm li svg{flex:none;margin-top:.12rem;color:var(--brass);opacity:.9}
.perm__scope{font-family:var(--font-mono);font-size:.84rem;color:var(--ink);overflow-wrap:anywhere}
.perm__desc{display:block;margin-top:.1rem;font-size:.8rem;color:var(--ink-3)}

/* Empty state */
.empty{margin:1.15rem 0 1.3rem;padding:1.1rem;text-align:center;font-size:.86rem;color:var(--ink-2);background:var(--surface-2);border:1px dashed var(--line-2);border-radius:var(--r-field)}

/* Callout (request context) */
.callout{margin:1.1rem 0;padding:.85rem .95rem;background:var(--surface-2);border:1px solid var(--line);border-left:2px solid var(--brass-line);border-radius:var(--r-chip);font-size:.88rem;color:var(--ink-2)}
.callout .mono{color:var(--ink)}

/* Success mark for result pages */
.result-mark{width:56px;height:56px;margin:0 auto 1.1rem;display:grid;place-items:center;border-radius:var(--r-pill);color:var(--brass);background:var(--brass-soft);border:1px solid var(--brass-line)}
.result-mark--muted{color:var(--ink-3);background:var(--surface-2);border-color:var(--line-2)}

/* Footer links */
.foot{margin:1.35rem 0 0;text-align:center;font-size:.85rem;color:var(--ink-3)}
.foot--split{margin-top:1.6rem;padding-top:1.15rem;border-top:1px solid var(--line)}
a{color:var(--brass);text-decoration:none;font-weight:550}
a:hover{text-decoration:underline;text-underline-offset:2px}
.link-quiet{color:var(--ink-2)}
.link-quiet:hover{color:var(--ink)}

/* Divider with label (alt sign-in) */
.rule{display:flex;align-items:center;gap:.8rem;margin:1.25rem 0;color:var(--ink-3);font-size:.75rem;letter-spacing:.08em;text-transform:uppercase}
.rule::before,.rule::after{content:"";height:1px;flex:1;background:var(--line)}

.stack>*+*{margin-top:.9rem}

.shell{width:min(100%,1080px);min-width:0;margin:0 auto;align-self:start;display:flex;flex-direction:column;gap:1.4rem;padding:1.5rem 0 3rem}
.shell-main{display:flex;min-width:0;flex-direction:column;gap:1.4rem}
.shell-heading{display:grid;gap:.3rem}
.shell-heading h1{margin:0;text-align:left;font-size:1.55rem;line-height:1.25;font-weight:640;letter-spacing:-.018em;color:var(--ink)}
.shell-heading p{max-width:720px;margin:0;color:var(--ink-2);font-size:.9rem}
.shell-bar{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding:1rem 1.4rem;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);box-shadow:var(--shadow)}
.shell-bar__brand{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}
.shell-bar .brand{flex-direction:row;margin:0;gap:.7rem}
.shell-bar .seal{width:34px;height:34px}
.shell-bar .brand__name{font-size:1.05rem;margin:0}
.shell-bar__badge{font-size:.66rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--brass);border:1px solid var(--brass-line);border-radius:var(--r-pill);padding:.16rem .55rem}
.shell-bar__actions{display:flex;align-items:center;justify-content:flex-end;gap:1rem;flex-wrap:wrap}
.shell-bar__right{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.shell-bar__right .btn{width:auto}
.shell-bar__who{font-size:.82rem;color:var(--ink-2)}
.shell-bar__who b{color:var(--ink);font-weight:600}
.shell-user{display:flex;align-items:center;gap:.6rem}
.shell-user .avatar{width:32px;height:32px;font-size:.78rem}
.shell-user__name{font-size:.88rem;font-weight:600;color:var(--ink)}
.shell-tabs{display:flex;gap:.25rem;flex-wrap:wrap;padding:.3rem;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-field)}
.shell-tab{padding:.5rem .95rem;border-radius:var(--r-chip);font-size:.88rem;font-weight:550;color:var(--ink-2)}
.shell-tab:hover{background:var(--surface-2);text-decoration:none;color:var(--ink)}
.shell-tab--active{background:var(--surface-3);color:var(--ink)}
.shell-tab--active:hover{background:var(--surface-3)}

.dash-panel{scroll-margin-top:2rem;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-card);overflow:hidden;box-shadow:var(--shadow);animation:rise .5s cubic-bezier(.2,.7,.2,1) both}
.dash-panel:nth-child(2){animation-delay:.05s}
.dash-panel:nth-child(3){animation-delay:.1s}
.dash-panel:nth-child(4){animation-delay:.15s}
.dash-panel:nth-child(5){animation-delay:.2s}
.dash-panel:nth-child(6){animation-delay:.25s}
.dash-panel::before{content:"";display:block;height:1px;background:linear-gradient(90deg,transparent,var(--brass-line),transparent)}
.dash-panel__head{padding:1.4rem 1.6rem 1.2rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.dash-panel__title{margin:0;font-size:1.1rem;font-weight:640;letter-spacing:-.01em;color:var(--ink)}
.dash-panel__desc{margin:.25rem 0 0;font-size:.86rem;color:var(--ink-2)}
.dash-panel__body{padding:0 1.6rem 1.6rem}

.dash-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:1px;background:var(--line);border-top:1px solid var(--line)}
.dash-list__item{background:var(--surface);padding:1.15rem 1.6rem;display:flex;align-items:center;justify-content:space-between;gap:1.5rem}
.dash-list__item--empty{padding:2rem 1.6rem;text-align:center;color:var(--ink-2);font-size:.9rem;background:var(--surface-2)}
@media (max-width:600px){.dash-list__item{flex-direction:column;align-items:flex-start;gap:1rem;padding:1.15rem}}
.dash-item__main{min-width:0;flex:1}
.dash-item__title{font-size:.95rem;font-weight:600;color:var(--ink);display:flex;align-items:center;gap:.6rem;margin-bottom:.2rem;flex-wrap:wrap}
.dash-item__meta{font-size:.85rem;color:var(--ink-2);display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
.dash-item__actions{flex:none;display:flex;gap:.5rem;align-items:center}
.dash-item__current{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--ok);border:1px solid var(--ok-soft);padding:.1rem .4rem;border-radius:var(--r-chip);background:var(--ok-soft)}
.dash-item__icon{color:var(--ink-3);display:flex;margin-right:.4rem}
.dash-panel__foot{padding:1.25rem 1.6rem;background:var(--surface);border-top:1px solid var(--line)}
.dash-panel__foot--end{display:flex;justify-content:flex-end}
.dash-chip-row{display:flex;gap:.75rem;flex-wrap:wrap}

.btn--sm{padding:.4rem .8rem;font-size:.82rem;border-radius:var(--r-chip)}

@media (max-width:600px){
  .shell-bar{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center}
  .shell-bar__brand{min-width:0}
  .shell-bar__actions{display:contents}
  .language-picker--shell{grid-column:2;grid-row:1}
  .language-picker--shell .language-picker__select{width:6.5rem;max-width:6.5rem;text-overflow:ellipsis}
  .shell-bar__right{grid-column:1/-1;grid-row:2;width:100%;justify-content:space-between}
  .shell-bar__who{flex-basis:100%}
}
@media (max-width:420px){
  .card{padding:1.35rem 1.15rem;border-radius:16px}
  h1{font-size:1.3rem}
  .btn-row{flex-direction:column}
  .stage{padding:1rem}
  .shell-bar__right{gap:.65rem}
  .language-picker__select{max-width:8.75rem}
}
@media (prefers-reduced-motion: reduce){
  *{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}
}
`

/** Concentric keyhole seal — the system's signature mark. currentColor = brass. */
const SEAL = `<span class="seal" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none">
<circle cx="24" cy="24" r="21" stroke="currentColor" stroke-width="1" opacity=".4"/>
<circle cx="24" cy="24" r="16.6" stroke="currentColor" stroke-width="1.3"/>
<g stroke="currentColor" stroke-width="1.3" stroke-linecap="round" opacity=".6">
<line x1="24" y1="3" x2="24" y2="5.7"/><line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(45 24 24)"/>
<line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(90 24 24)"/><line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(135 24 24)"/>
<line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(180 24 24)"/><line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(225 24 24)"/>
<line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(270 24 24)"/><line x1="24" y1="3" x2="24" y2="5.7" transform="rotate(315 24 24)"/>
</g>
<circle cx="24" cy="20.4" r="3.7" stroke="currentColor" stroke-width="2"/>
<path d="M23.1 23.2 L21.7 31 H26.3 L24.9 23.2 Z" fill="currentColor"/>
</svg></span>`

/**
 * Avatar image, or monogram initials when the account has no picture.
 * Uploaded avatars are referenced by their same-origin path so server-rendered
 * pages need no absolute issuer URL.
 */
export function avatarMarkup(user: User, extraClass = "", attributes = ""): string {
  const className = `avatar${extraClass === "" ? "" : ` ${extraClass}`}`
  const extra = attributes === "" ? "" : ` ${attributes}`
  const source = user.avatarKey === null ? user.picture : avatarPath(user.avatarKey)
  if (source === null) {
    const label = user.name ?? user.alias
    return `<div class="${className} avatar--fallback"${extra} aria-hidden="true">${escapeHtml(initialsOf(label))}</div>`
  }
  return `<img class="${className}"${extra} src="${escapeHtml(source)}" alt="" referrerpolicy="no-referrer">`
}

/** Two-letter monogram derived from a display name or email local part. */
export function initialsOf(value: string): string {
  const base = value.includes("@") ? (value.split("@")[0] ?? value) : value
  const parts = base
    .trim()
    .split(/[\s._-]+/)
    .filter(Boolean)
  const first = parts[0] ?? ""
  const second = parts[1] ?? ""
  return (second ? (first[0] ?? "") + (second[0] ?? "") : first.slice(0, 2) || "?").toUpperCase()
}

/** Brand lockup used at the head of every page. */
export function brandHeader(): string {
  return `<div class="brand">${SEAL}<div class="brand__name">KeyForge</div></div>`
}

/** Small inline glyphs (kept local so views stay declarative). */
export const icons = {
  alert: `<svg class="alert__icon" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 8v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="currentColor"/><path d="M12 3 2.5 20h19L12 3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>`,
  key: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="4.2" stroke="currentColor" stroke-width="1.8"/><path d="M11 11 20 20m-3 0 2.5-2.5M14 17l2.5-2.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  check: `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5 12.5 4.5 4.5L19 7.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  cross: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 7l10 10M17 7 7 17" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>`,
} as const

const SCOPE_DESCRIPTIONS: Readonly<Record<string, string>> = {
  openid: "Confirm your identity",
  profile: "Your name and profile details",
  email: "Your email address",
  offline_access: "Stay signed in while you're away",
  address: "Your postal address",
  phone: "Your phone number",
  groups: "Your group memberships",
}

export function permissionList(i18n: I18n, scopes: readonly string[]): string {
  if (scopes.length === 0) {
    return `<div class="empty">${escapeHtml(i18n.t("This app isn't requesting any specific permissions."))}</div>`
  }
  const items = scopes
    .map((scope) => {
      const desc = SCOPE_DESCRIPTIONS[scope]
      const descHtml =
        desc === undefined ? "" : `<span class="perm__desc">${escapeHtml(i18n.t(desc))}</span>`
      return `<li>${icons.key}<div><span class="perm__scope">${escapeHtml(scope)}</span>${descHtml}</div></li>`
    })
    .join("")
  return `<ul class="perm">${items}</ul>`
}

type LanguagePickerPlacement = "card" | "shell"

function languagePicker(i18n: I18n, placement: LanguagePickerPlacement): string {
  const selected = (preference: string) => (i18n.preference === preference ? " selected" : "")
  return `<form class="language-picker language-picker--${placement}" method="get" action="/language" data-language-picker>
  <svg class="language-picker__icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.6"/><path d="M3.8 12h16.4M12 3.5c2.1 2.25 3.2 5.08 3.2 8.5S14.1 18.25 12 20.5C9.9 18.25 8.8 15.42 8.8 12S9.9 5.75 12 3.5Z" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
  <label class="language-picker__field">
    <span class="sr-only">${escapeHtml(i18n.t("Language"))}</span>
    <select class="language-picker__select" name="language" aria-label="${escapeHtml(i18n.t("Language"))}">
      <option value="auto"${selected("auto")}>${escapeHtml(i18n.t("Follow browser"))}</option>
      <option value="en"${selected("en")}>English</option>
      <option value="zh-CN"${selected("zh-CN")}>简体中文</option>
      <option value="ja"${selected("ja")}>日本語</option>
    </select>
  </label>
  <input type="hidden" name="return_to" value="${escapeHtml(i18n.returnTo)}">
  <noscript><button class="btn btn--ghost language-picker__apply" type="submit">${escapeHtml(i18n.t("Apply"))}</button></noscript>
</form>`
}

export function htmlLayout(
  i18n: I18n,
  title: string,
  body: string,
  extraStyles?: string,
  languagePlacement: "card" | "none" = "card",
): string {
  const extra = extraStyles === undefined ? "" : `<style>${extraStyles}</style>`
  const stageBody =
    languagePlacement === "card"
      ? `<div class="stage-stack">${body}${languagePicker(i18n, "card")}</div>`
      : body
  return `<!DOCTYPE html>
<html lang="${i18n.locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0a0b0f" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f3f1ea" media="(prefers-color-scheme: light)">
<title>${escapeHtml(title)}</title>
<style>${BASE_STYLES}</style>${extra}
</head>
<body><div class="stage">${stageBody}</div><script src="/assets/forms.js" defer></script></body>
</html>`
}

export type ShellTab = { readonly label: string; readonly href: string; readonly active: boolean }

export type AppShellOptions = {
  readonly i18n: I18n
  readonly title: string
  readonly heading: string
  readonly headingDescription?: string
  readonly badge?: string
  readonly barRight: string
  readonly tabs: readonly ShellTab[]
  readonly content: string
  readonly extraStyles?: string
}

export function appShell(options: AppShellOptions): string {
  const badge =
    options.badge === undefined
      ? ""
      : `<span class="shell-bar__badge">${escapeHtml(options.badge)}</span>`
  const tabs = options.tabs
    .map((tab) => {
      const active = tab.active ? " shell-tab--active" : ""
      const current = tab.active ? ' aria-current="page"' : ""
      return `<a class="shell-tab${active}" href="${tab.href}"${current}>${escapeHtml(tab.label)}</a>`
    })
    .join("")
  const heading =
    options.headingDescription === undefined
      ? `<h1 class="sr-only">${escapeHtml(options.heading)}</h1>`
      : `<header class="shell-heading"><h1>${escapeHtml(options.heading)}</h1><p>${escapeHtml(options.headingDescription)}</p></header>`
  const body = `<div class="shell">
  <div class="shell-bar">
    <div class="shell-bar__brand">${brandHeader()}${badge}</div>
    <div class="shell-bar__actions">
      ${languagePicker(options.i18n, "shell")}
      <div class="shell-bar__right">${options.barRight}</div>
    </div>
  </div>
  <nav class="shell-tabs" aria-label="${escapeHtml(options.i18n.t("Sections"))}">${tabs}</nav>
  <main class="shell-main">${heading}${options.content}</main>
</div>`
  return htmlLayout(options.i18n, options.title, body, options.extraStyles, "none")
}
