import { readFileSync } from "node:fs"
import { spawnSync } from "node:child_process"

const listed = spawnSync(
  "git",
  ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  { encoding: "utf8" },
)
if (listed.status !== 0) {
  process.stderr.write(listed.stderr ?? "unable to enumerate repository files\n")
  process.exit(2)
}

const files = listed.stdout.split("\0").filter(Boolean)
const findings = []
const knownSecretPatterns = [
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ["GitHub token", /\b(?:gh[opsu]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g],
  ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ["Google API key", /\bAIza[A-Za-z0-9_-]{35}\b/g],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g],
  ["Stripe live key", /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g],
]
const assignment = /\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*["']([^"'\s]{16,})["']/gi
// One-way password records are safe to commit and are used for constant-time
// unknown-account verification; they are not credentials or reusable secrets.
const safeFixture =
  /^(?:https?:\/\/|scrypt\$|test|s3cr3t|example|placeholder|replace|changeme|0{16,})/i

for (const file of files) {
  if (file === ".dev.vars" || /^\.env(?:\.|$)/.test(file)) {
    findings.push(`${file}: secret environment file must not be tracked`)
    continue
  }
  let text
  try {
    const buffer = readFileSync(file)
    if (buffer.length > 2_000_000 || buffer.includes(0)) continue
    text = buffer.toString("utf8")
  } catch {
    continue
  }
  for (const [label, pattern] of knownSecretPatterns) {
    pattern.lastIndex = 0
    if (pattern.test(text)) findings.push(`${file}: possible ${label}`)
  }
  assignment.lastIndex = 0
  for (const match of text.matchAll(assignment)) {
    const value = match[1] ?? ""
    if (!safeFixture.test(value) && !value.startsWith("${")) {
      findings.push(`${file}: possible hard-coded secret assignment`)
    }
  }
}

if (findings.length > 0) {
  process.stderr.write(`${[...new Set(findings)].join("\n")}\n`)
  process.exit(1)
}
process.stdout.write(`Secret scan passed (${files.length} repository files checked).\n`)
