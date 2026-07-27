#!/usr/bin/env node

import { spawn } from "node:child_process"
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { createInterface } from "node:readline/promises"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const PNPM = process.platform === "win32" ? "pnpm.cmd" : "pnpm"
const REQUIRED_SECRETS = [
  "EMAIL_FROM",
  "READINESS_PROBE_TOKEN",
  "REQUEST_HASH_SECRET",
  "RESEND_API_KEY",
]
const READINESS_TOKEN_PATTERN = /^[A-Za-z0-9._~-]{32,256}$/
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
const MAX_PEAK_DAILY_AUDIT_ROWS = 28_800
const TARGETS = {
  staging: {
    database: "keyforge_staging",
    origin: "https://auth-staging.pangda.app",
    tokenVariable: "KEYFORGE_STAGING_READINESS_TOKEN",
  },
  production: {
    database: "keyforge",
    origin: "https://auth.pangda.app",
    tokenVariable: "KEYFORGE_PRODUCTION_READINESS_TOKEN",
  },
}

function usage(exitCode = 0) {
  const output = exitCode === 0 ? console.log : console.error
  output(`Usage: node scripts/release.mjs <staging|production> [--plan] [--yes]

Options:
  --plan  Print the release sequence without running commands or making requests.
  --yes   Skip the interactive production confirmation (intended for CI).

Readiness token:
  Export the target-specific variable (${TARGETS.staging.tokenVariable} or
  ${TARGETS.production.tokenVariable}), or the generic READINESS_PROBE_TOKEN fallback.`)
  process.exitCode = exitCode
}

function parseArguments(argv) {
  const normalized = argv.filter((argument) => argument !== "--")
  if (normalized.includes("--help") || normalized.includes("-h")) return { help: true }
  const rawEnvironment = normalized[0]
  const environment = rawEnvironment === "prod" ? "production" : rawEnvironment
  if (!(environment in TARGETS)) throw new Error("target must be staging or production")

  const flags = new Set(normalized.slice(1))
  const unknown = [...flags].filter((flag) => !["--plan", "--yes"].includes(flag))
  if (unknown.length > 0) throw new Error(`unknown option: ${unknown.join(", ")}`)
  return {
    environment,
    plan: flags.has("--plan"),
    yes: flags.has("--yes"),
  }
}

function quoteArgument(value) {
  return /^[A-Za-z0-9_./:@=-]+$/.test(value)
    ? value
    : `'${value.replaceAll("'", `'"'"'`)}'`
}

function formatCommand(command, args) {
  return [command, ...args].map(quoteArgument).join(" ")
}

function childEnvironment(extra = {}) {
  const environment = { ...process.env, ...extra }
  // The readiness credential is only used by this process for HTTPS probes.
  // Do not expose it to package scripts, git, Wrangler, or their subprocesses.
  delete environment.READINESS_PROBE_TOKEN
  delete environment.KEYFORGE_STAGING_READINESS_TOKEN
  delete environment.KEYFORGE_PRODUCTION_READINESS_TOKEN
  return environment
}

async function run(command, args, options = {}) {
  console.log(`\n$ ${formatCommand(command, args)}`)
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      env: childEnvironment(options.environment),
      stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
    })
    let stdout = ""
    if (options.capture) {
      child.stdout.setEncoding("utf8")
      child.stdout.on("data", (chunk) => {
        stdout += chunk
      })
    }
    child.once("error", rejectPromise)
    child.once("close", (code, signal) => {
      if (code === 0) resolvePromise(stdout)
      else {
        const detail = signal === null ? `exit code ${code}` : `signal ${signal}`
        rejectPromise(new Error(`${formatCommand(command, args)} failed with ${detail}`))
      }
    })
  })
}

function pnpm(args, options) {
  return run(PNPM, args, options)
}

async function captureGit(args) {
  return (await run("git", args, { capture: true })).trim()
}

function readReadinessToken(target) {
  const token = process.env[target.tokenVariable] ?? process.env.READINESS_PROBE_TOKEN ?? ""
  if (!READINESS_TOKEN_PATTERN.test(token)) {
    throw new Error(
      `export ${target.tokenVariable} (or READINESS_PROBE_TOKEN) with the 32-256 character probe credential before releasing`,
    )
  }
  return token
}

async function assertGitReleaseState(environment) {
  const status = await captureGit(["status", "--porcelain=v1", "--untracked-files=all"])
  if (status !== "") {
    throw new Error("release requires a clean working tree; commit or stash every change first")
  }
  const branch = await captureGit(["branch", "--show-current"])
  if (environment === "production" && branch !== "main") {
    throw new Error(`production release must run from main (current branch: ${branch || "detached"})`)
  }
  return captureGit(["rev-parse", "--short=12", "HEAD"])
}

async function confirmProduction(environment, yes) {
  if (environment !== "production" || yes) return
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("non-interactive production release requires --yes")
  }
  const prompt = createInterface({ input: process.stdin, output: process.stdout })
  try {
    const answer = await prompt.question(
      `Type production to migrate and deploy ${TARGETS.production.origin}: `,
    )
    if (answer.trim() !== "production") throw new Error("production release cancelled")
  } finally {
    prompt.close()
  }
}

function assertRequiredSecrets(raw) {
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error("Wrangler returned invalid JSON while listing remote secrets")
  }
  if (!Array.isArray(parsed)) throw new Error("Wrangler secret list returned an unexpected shape")
  const names = new Set(
    parsed
      .filter((item) => typeof item === "object" && item !== null)
      .map((item) => item.name)
      .filter((name) => typeof name === "string"),
  )
  const missing = REQUIRED_SECRETS.filter((name) => !names.has(name))
  if (missing.length > 0) throw new Error(`remote Worker is missing secrets: ${missing.join(", ")}`)
}

function peakDailyRowsFromWrangler(raw) {
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error("Wrangler returned invalid JSON for the production audit-volume query")
  }
  const envelopes = Array.isArray(parsed) ? parsed : [parsed]
  const row = envelopes.find(
    (entry) => typeof entry === "object" && entry !== null && Array.isArray(entry.results),
  )?.results?.[0]
  const value =
    typeof row === "object" && row !== null ? Number(row.peak_daily_rows ?? Number.NaN) : Number.NaN
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("production audit-volume query did not return a non-negative integer")
  }
  return value
}

async function runLocalGates(environment) {
  await pnpm(["install", "--frozen-lockfile"])
  await pnpm(["exec", "wrangler", "whoami"])
  await pnpm([`validate:deploy:${environment}`])

  const secretList = await pnpm(
    ["exec", "wrangler", "secret", "list", "--env", environment, "--format", "json"],
    { capture: true },
  )
  assertRequiredSecrets(secretList)

  await pnpm(["check"])
  await pnpm(["test:coverage"])
  await pnpm(["demo:selftest"])
  await pnpm(["audit", "--audit-level", "moderate"])
  await pnpm(["secrets:scan"])
  await pnpm(["exec", "wrangler", "deploy", "--dry-run", "--strict", "--env", environment])
}

async function checkProductionCapacity(target) {
  await pnpm(["exec", "wrangler", "d1", "info", target.database, "--env", "production"])
  const query =
    "SELECT COALESCE(MAX(daily_rows), 0) AS peak_daily_rows FROM (" +
    "SELECT created_at / 86400 AS utc_day, COUNT(*) AS daily_rows " +
    "FROM audit_logs WHERE created_at >= unixepoch() - 30 * 86400 GROUP BY utc_day)"
  const raw = await pnpm(
    [
      "exec",
      "wrangler",
      "d1",
      "execute",
      target.database,
      "--env",
      "production",
      "--remote",
      "--json",
      "--command",
      query,
    ],
    { capture: true },
  )
  const peakDailyRows = peakDailyRowsFromWrangler(raw)
  console.log(`Production peak audit volume (last 30 days): ${peakDailyRows} rows/day`)
  if (peakDailyRows > MAX_PEAK_DAILY_AUDIT_ROWS) {
    throw new Error(
      `production peak audit volume exceeds the ${MAX_PEAK_DAILY_AUDIT_ROWS} rows/day cleanup capacity`,
    )
  }
}

async function createPreMigrationBackup(environment, target) {
  const directory = await mkdtemp(join(tmpdir(), `keyforge-${environment}-release-`))
  await chmod(directory, 0o700)
  const timeTravelPath = join(directory, "time-travel.json")
  const schemaPath = join(directory, `${target.database}-schema.sql`)

  const timeTravel = await pnpm(
    ["exec", "wrangler", "d1", "time-travel", "info", target.database, "--env", environment, "--json"],
    { capture: true },
  )
  await writeFile(timeTravelPath, timeTravel, { mode: 0o600 })
  await pnpm([
    "exec",
    "wrangler",
    "d1",
    "export",
    target.database,
    "--env",
    environment,
    "--remote",
    "--no-data",
    "--skip-confirmation",
    "--output",
    schemaPath,
  ])
  await chmod(schemaPath, 0o600)
  console.log(`Pre-migration recovery metadata: ${directory}`)
  return directory
}

async function migrateAndDeploy(environment, target, commit) {
  await pnpm([
    "exec",
    "wrangler",
    "d1",
    "migrations",
    "list",
    target.database,
    "--env",
    environment,
    "--remote",
  ])
  await pnpm(
    [
      "exec",
      "wrangler",
      "d1",
      "migrations",
      "apply",
      target.database,
      "--env",
      environment,
      "--remote",
    ],
    { environment: { CI: "1" } },
  )

  const message = `release ${environment} ${commit} ${new Date().toISOString()}`
  await pnpm([
    "exec",
    "wrangler",
    "deploy",
    "--strict",
    "--env",
    environment,
    "--message",
    message,
  ])
}

function objectValue(value) {
  return typeof value === "object" && value !== null ? value : null
}

async function fetchJsonWithRetry(label, url, init, validate) {
  let lastError = new Error(`${label} did not run`)
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    try {
      const response = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const body = JSON.parse(await response.text())
      validate(body)
      return body
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))
      if (attempt === 10) break
      console.warn(`${label} attempt ${attempt}/10 failed; retrying without printing response data`)
      await delay(Math.min(1_000 * attempt, 5_000))
    }
  }
  throw new Error(`${label} failed after 10 attempts: ${lastError.message}`)
}

async function verifyDeployment(target, readinessToken) {
  await fetchJsonWithRetry("liveness", `${target.origin}/health`, {}, (body) => {
    if (objectValue(body)?.status !== "ok") throw new Error("unexpected liveness response")
  })

  await fetchJsonWithRetry(
    "authenticated readiness",
    `${target.origin}/health/ready`,
    { headers: { authorization: `Bearer ${readinessToken}` } },
    (body) => {
      const response = objectValue(body)
      const checks = objectValue(response?.checks)
      if (response?.status !== "ready" || checks === null || Object.keys(checks).length === 0) {
        throw new Error("readiness did not report ready")
      }
      if (Object.values(checks).some((check) => objectValue(check)?.status !== "ok")) {
        throw new Error("one or more readiness dependencies failed")
      }
    },
  )

  const discovery = await fetchJsonWithRetry(
    "OIDC discovery",
    `${target.origin}/.well-known/openid-configuration`,
    {},
    (body) => {
      const response = objectValue(body)
      if (response?.issuer !== target.origin) throw new Error("discovery issuer mismatch")
      const jwksUri = typeof response?.jwks_uri === "string" ? response.jwks_uri : ""
      if (new URL(jwksUri).origin !== target.origin) throw new Error("discovery jwks_uri mismatch")
    },
  )
  const jwksUri = objectValue(discovery).jwks_uri
  await fetchJsonWithRetry("OIDC JWKS", jwksUri, {}, (body) => {
    const keys = objectValue(body)?.keys
    if (!Array.isArray(keys) || keys.length === 0) throw new Error("JWKS has no public keys")
    for (const key of keys) {
      const jwk = objectValue(key)
      if (jwk === null || PRIVATE_JWK_FIELDS.some((field) => field in jwk)) {
        throw new Error("JWKS contains invalid or private key material")
      }
    }
  })
}

function printPlan(environment, target) {
  const database = target.database
  const commands = [
    [PNPM, ["install", "--frozen-lockfile"]],
    [PNPM, ["exec", "wrangler", "whoami"]],
    [PNPM, [`validate:deploy:${environment}`]],
    [PNPM, ["exec", "wrangler", "secret", "list", "--env", environment, "--format", "json"]],
    [PNPM, ["check"]],
    [PNPM, ["test:coverage"]],
    [PNPM, ["demo:selftest"]],
    [PNPM, ["audit", "--audit-level", "moderate"]],
    [PNPM, ["secrets:scan"]],
    [PNPM, ["exec", "wrangler", "deploy", "--dry-run", "--strict", "--env", environment]],
    ...(environment === "production"
      ? [
          [PNPM, ["exec", "wrangler", "d1", "info", database, "--env", environment]],
          [PNPM, ["exec", "wrangler", "d1", "execute", database, "--env", environment, "--remote", "--json", "--command", "<audit-capacity-query>"]],
        ]
      : []),
    [PNPM, ["exec", "wrangler", "d1", "time-travel", "info", database, "--env", environment, "--json"]],
    [PNPM, ["exec", "wrangler", "d1", "export", database, "--env", environment, "--remote", "--no-data", "--skip-confirmation", "--output", "<temporary-schema-path>"]],
    [PNPM, ["exec", "wrangler", "d1", "migrations", "list", database, "--env", environment, "--remote"]],
    [PNPM, ["exec", "wrangler", "d1", "migrations", "apply", database, "--env", environment, "--remote"]],
    [PNPM, ["exec", "wrangler", "deploy", "--strict", "--env", environment, "--message", "<release-message>"]],
  ]
  console.log(`Release plan for ${environment} (${target.origin}):`)
  if (environment === "production") {
    console.log(`- Inspect D1 capacity and enforce <= ${MAX_PEAK_DAILY_AUDIT_ROWS} peak audit rows/day.`)
  }
  for (const [command, args] of commands) console.log(`- ${formatCommand(command, args)}`)
  console.log("- Retry and validate liveness, authenticated readiness, OIDC discovery, and public JWKS.")
}

async function main() {
  let argumentsValue
  try {
    argumentsValue = parseArguments(process.argv.slice(2))
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    usage(1)
    return
  }
  if (argumentsValue.help) {
    usage()
    return
  }

  const { environment, plan, yes } = argumentsValue
  const target = TARGETS[environment]
  if (plan) {
    printPlan(environment, target)
    return
  }

  let backupDirectory
  let remoteMutationStarted = false
  let success = false
  try {
    const readinessToken = readReadinessToken(target)
    const commit = await assertGitReleaseState(environment)
    await confirmProduction(environment, yes)
    await runLocalGates(environment)
    if (environment === "production") await checkProductionCapacity(target)
    backupDirectory = await createPreMigrationBackup(environment, target)
    remoteMutationStarted = true
    await migrateAndDeploy(environment, target, commit)
    await verifyDeployment(target, readinessToken)
    success = true
    console.log(`\nRelease complete: ${environment} ${commit} -> ${target.origin}`)
  } catch (error) {
    console.error(`\nRelease failed: ${error instanceof Error ? error.message : error}`)
    if (remoteMutationStarted) {
      console.error(
        "Remote migrations or deployment may already be applied. Inspect readiness and prefer a reviewed roll-forward; do not blindly roll back across schema changes.",
      )
    }
    process.exitCode = 1
  } finally {
    if (backupDirectory !== undefined) {
      if (success) {
        await rm(backupDirectory, { recursive: true, force: true })
        console.log("Removed the temporary schema-only release backup after successful verification.")
      } else {
        console.error(`Preserved pre-migration recovery metadata at ${backupDirectory}`)
      }
    }
  }
}

await main()
