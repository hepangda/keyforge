export function relativeTime(iso: string | undefined | null, now = Date.now()): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const diff = (t - now) / 1000
  const abs = Math.abs(diff)
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  if (abs < 60) return rtf.format(Math.round(diff), 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day')
  if (abs < 86400 * 365) return rtf.format(Math.round(diff / 86400 / 30), 'month')
  return rtf.format(Math.round(diff / 86400 / 365), 'year')
}

export function absoluteTime(iso: string | undefined | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

interface UAInfo {
  browser: string
  os: string
}

export function parseUserAgent(ua: string): UAInfo {
  if (!ua) return { browser: 'Unknown', os: '' }
  const browser =
    matchOne(ua, /Edg\/[\d.]+/, 'Edge') ||
    matchOne(ua, /OPR\/[\d.]+/, 'Opera') ||
    matchOne(ua, /Firefox\/[\d.]+/, 'Firefox') ||
    matchOne(ua, /Chrome\/[\d.]+/, 'Chrome') ||
    matchOne(ua, /Safari\/[\d.]+/, 'Safari') ||
    matchOne(ua, /curl\/[\d.]+/, 'curl') ||
    'Unknown'
  const os =
    matchOne(ua, /Windows NT [\d.]+/, 'Windows') ||
    matchOne(ua, /Mac OS X [\d_.]+/, 'macOS') ||
    matchOne(ua, /iPhone OS [\d_]+/, 'iOS') ||
    matchOne(ua, /Android [\d.]+/, 'Android') ||
    matchOne(ua, /Linux/, 'Linux') ||
    ''
  return { browser, os }
}

function matchOne(ua: string, re: RegExp, label: string): string | null {
  return re.test(ua) ? label : null
}
