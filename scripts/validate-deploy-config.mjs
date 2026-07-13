#!/usr/bin/env node

import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"

const REMOTE_ENVIRONMENTS = new Set(["staging", "production"])
const REQUIRED_DURABLE_OBJECTS = new Map([
  ["AUTHORIZATION_CODE", "AuthorizationCodeDO"],
  ["ONE_TIME_TOKEN", "OneTimeTokenDO"],
  ["WEBAUTHN_CHALLENGE", "WebAuthnChallengeDO"],
  ["REFRESH_TOKEN_FAMILY", "RefreshTokenFamilyDO"],
  ["RATE_LIMIT", "RateLimitDO"],
])
const REQUIRED_REMOTE_SECRETS = new Set([
  "RESEND_API_KEY",
  "EMAIL_FROM",
  "REQUEST_HASH_SECRET",
  "READINESS_PROBE_TOKEN",
])
const EXPECTED_ENVIRONMENT = {
  staging: {
    workerName: "keyforge-staging",
    issuer: "https://auth-staging.pangda.app",
    databaseName: "keyforge_staging",
    queueName: "keyforge-audit-staging",
    deadLetterQueueName: "keyforge-audit-staging-dlq",
    emailQueueName: "keyforge-email-staging",
    emailDeadLetterQueueName: "keyforge-email-staging-dlq",
    auditRetentionDays: 90,
  },
  production: {
    workerName: "keyforge",
    issuer: "https://auth.pangda.app",
    databaseName: "keyforge",
    queueName: "keyforge-audit",
    deadLetterQueueName: "keyforge-audit-dlq",
    emailQueueName: "keyforge-email",
    emailDeadLetterQueueName: "keyforge-email-dlq",
    auditRetentionDays: 365,
  },
}
const NUMERIC_BOUNDS = new Map([
  ["KEY_ROTATION_INTERVAL_SECONDS", [86_400, 31_536_000]],
  ["TERMINAL_DATA_RETENTION_DAYS", [1, 3_650]],
  ["AUDIT_D1_RETENTION_DAYS", [1, 365]],
  ["MAINTENANCE_BATCH_SIZE", [1, 100]],
  ["MAINTENANCE_LEASE_SECONDS", [60, 3_600]],
])

function parseTables(source) {
  const tables = new Map()
  let current = null

  for (const line of source.split(/\r?\n/)) {
    const header = line.match(/^\s*\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/)
    if (header) {
      current = header[1].trim()
      const bodies = tables.get(current) ?? []
      bodies.push([])
      tables.set(current, bodies)
      continue
    }
    if (current !== null) tables.get(current).at(-1).push(line)
  }

  return new Map(
    [...tables].map(([name, bodies]) => [name, bodies.map((lines) => lines.join("\n"))]),
  )
}

function onlyTable(tables, name) {
  const matches = tables.get(name) ?? []
  if (matches.length !== 1) throw new Error(`expected exactly one [${name}] section`)
  return matches[0]
}

function stringValue(body, key) {
  const match = body.match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, "m"))
  if (!match) throw new Error(`${key} is missing or is not a TOML string`)
  return match[1]
}

function booleanValue(body, key) {
  const match = body.match(new RegExp(`^\\s*${key}\\s*=\\s*(true|false)\\s*(?:#.*)?$`, "m"))
  if (!match) throw new Error(`${key} is missing or is not a TOML boolean`)
  return match[1] === "true"
}

function stringArrayValue(body, key) {
  const match = body.match(new RegExp(`^\\s*${key}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "m"))
  if (!match) throw new Error(`${key} is missing or is not a TOML string array`)
  const raw = match[1]
  const values = [...raw.matchAll(/"([^"]+)"/g)].map((entry) => entry[1])
  if (raw.replaceAll(/"[^"]+"/g, "").replaceAll(/[\s,]/g, "") !== "") {
    throw new Error(`${key} is not a valid TOML string array`)
  }
  return values
}

function arrayEntry(tables, section, binding) {
  const entries = tables.get(section) ?? []
  const matches = entries.filter((body) => stringValue(body, "binding") === binding)
  if (matches.length !== 1) {
    throw new Error(`[${section}] must contain exactly one ${binding} binding`)
  }
  return matches[0]
}

function rejectPlaceholder(value, label) {
  const normalized = value.toLowerCase().replaceAll("-", "")
  if (
    normalized.length === 0 ||
    /^0+$/.test(normalized) ||
    /placeholder|replace|changeme|example|todo|your[_-]/i.test(value)
  ) {
    throw new Error(`${label} still contains a placeholder value`)
  }
}

function remoteResources(tables, environment) {
  const prefix = `env.${environment}`
  const d1 = arrayEntry(tables, `${prefix}.d1_databases`, "DB")
  const kv = arrayEntry(tables, `${prefix}.kv_namespaces`, "KV")
  const auditQueueProducer = arrayEntry(tables, `${prefix}.queues.producers`, "AUDIT_QUEUE")
  const emailQueueProducer = arrayEntry(tables, `${prefix}.queues.producers`, "EMAIL_QUEUE")
  const queueConsumers = tables.get(`${prefix}.queues.consumers`) ?? []
  const auditQueueName = stringValue(auditQueueProducer, "queue")
  const emailQueueName = stringValue(emailQueueProducer, "queue")
  const auditConsumers = queueConsumers.filter(
    (consumer) => stringValue(consumer, "queue") === auditQueueName,
  )
  const emailConsumers = queueConsumers.filter(
    (consumer) => stringValue(consumer, "queue") === emailQueueName,
  )

  if (queueConsumers.length !== 2 || auditConsumers.length !== 1 || emailConsumers.length !== 1) {
    throw new Error(
      `[${prefix}.queues.consumers] must contain exactly one audit and one email consumer`,
    )
  }

  return {
    databaseId: stringValue(d1, "database_id"),
    databaseName: stringValue(d1, "database_name"),
    kvId: stringValue(kv, "id"),
    queueName: auditQueueName,
    consumerQueueName: stringValue(auditConsumers[0], "queue"),
    deadLetterQueueName: stringValue(auditConsumers[0], "dead_letter_queue"),
    emailQueueName,
    emailConsumerQueueName: stringValue(emailConsumers[0], "queue"),
    emailDeadLetterQueueName: stringValue(emailConsumers[0], "dead_letter_queue"),
    migrationsDirectory: stringValue(d1, "migrations_dir"),
  }
}

function assertDistinct(left, right, label) {
  if (left === right) throw new Error(`staging and production must not share ${label}`)
}

export function validateDeployConfig(source, environment) {
  if (!REMOTE_ENVIRONMENTS.has(environment)) {
    throw new Error("target must be staging or production")
  }

  const tables = parseTables(source)
  if (/^\s*AUDIT_ARCHIVE_RETENTION_DAYS\s*=/m.test(source)) {
    throw new Error("AUDIT_ARCHIVE_RETENTION_DAYS is forbidden; audit rows must not be archived")
  }
  const r2Sections = [...tables.keys()].filter((name) => name.endsWith("r2_buckets"))
  if (r2Sections.length > 0) {
    throw new Error(`R2 bindings are forbidden: ${r2Sections.join(", ")}`)
  }
  const prefix = `env.${environment}`
  const root = onlyTable(tables, prefix)
  const vars = onlyTable(tables, `${prefix}.vars`)
  const secrets = onlyTable(tables, `${prefix}.secrets`)
  const trigger = onlyTable(tables, `${prefix}.triggers`)
  const resources = remoteResources(tables, environment)
  const expected = EXPECTED_ENVIRONMENT[environment]
  const otherEnvironment = environment === "staging" ? "production" : "staging"
  const otherResources = remoteResources(tables, otherEnvironment)

  if (booleanValue(root, "workers_dev")) {
    throw new Error(`${environment} must set workers_dev=false`)
  }

  const workerName = stringValue(root, "name")
  rejectPlaceholder(workerName, `${environment} Worker name`)
  if (workerName !== expected.workerName) {
    throw new Error(`${environment} Worker name must be ${expected.workerName}`)
  }
  const otherWorkerName = stringValue(onlyTable(tables, `env.${otherEnvironment}`), "name")
  assertDistinct(workerName, otherWorkerName, "a Worker name")

  const configuredEnvironment = stringValue(vars, "ENVIRONMENT")
  if (configuredEnvironment !== environment) {
    throw new Error(`ENVIRONMENT=${configuredEnvironment} does not match --env ${environment}`)
  }
  if (stringValue(vars, "EMAIL_DELIVERY_MODE") !== "resend") {
    throw new Error(`${environment} must set EMAIL_DELIVERY_MODE=resend`)
  }
  const signup = stringValue(vars, "ALLOW_SELF_SIGNUP")
  if (signup !== "true" && signup !== "false") {
    throw new Error("ALLOW_SELF_SIGNUP must be explicitly true or false")
  }
  for (const [name, [minimum, maximum]] of NUMERIC_BOUNDS) {
    const raw = stringValue(vars, name)
    const parsed = Number(raw)
    if (!/^\d+$/.test(raw) || !Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
      throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`)
    }
  }
  if (Number(stringValue(vars, "AUDIT_D1_RETENTION_DAYS")) !== expected.auditRetentionDays) {
    throw new Error(
      `${environment} AUDIT_D1_RETENTION_DAYS must be ${expected.auditRetentionDays}`,
    )
  }
  const requiredSecrets = stringArrayValue(secrets, "required")
  if (
    requiredSecrets.length !== REQUIRED_REMOTE_SECRETS.size ||
    requiredSecrets.some((name) => !REQUIRED_REMOTE_SECRETS.has(name))
  ) {
    throw new Error(
      `${environment} required secrets must be exactly ${[...REQUIRED_REMOTE_SECRETS].join(", ")}`,
    )
  }

  const issuerText = stringValue(vars, "ISSUER")
  let issuer
  try {
    issuer = new URL(issuerText)
  } catch {
    throw new Error(`${environment} ISSUER is not a valid URL`)
  }
  if (
    issuer.protocol !== "https:" ||
    issuer.username !== "" ||
    issuer.password !== "" ||
    issuer.pathname !== "/" ||
    issuer.search !== "" ||
    issuer.hash !== ""
  ) {
    throw new Error(`${environment} ISSUER must be a canonical HTTPS origin`)
  }
  if (issuerText !== expected.issuer) {
    throw new Error(`${environment} ISSUER must be ${expected.issuer}`)
  }

  const route = root.match(
    /^\s*routes\s*=\s*\[\s*\{\s*pattern\s*=\s*"([^"]+)"\s*,\s*custom_domain\s*=\s*(true|false)\s*}\s*]\s*$/m,
  )
  if (!route || route[2] !== "true") {
    throw new Error(`${environment} must define one custom-domain route`)
  }
  if (route[1] !== issuer.hostname || issuer.port !== "") {
    throw new Error(`${environment} route must exactly match the ISSUER hostname`)
  }

  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(resources.databaseId)) {
    throw new Error(`${environment} D1 database_id is not a UUID`)
  }
  if (!/^[0-9a-f]{32}$/i.test(resources.kvId)) {
    throw new Error(`${environment} KV id is not a 32-character hexadecimal ID`)
  }
  rejectPlaceholder(resources.databaseId, `${environment} D1 database_id`)
  rejectPlaceholder(resources.kvId, `${environment} KV id`)

  for (const [label, actual, wanted] of [
    ["D1 database_name", resources.databaseName, expected.databaseName],
    ["audit Queue", resources.queueName, expected.queueName],
    ["audit DLQ", resources.deadLetterQueueName, expected.deadLetterQueueName],
    ["email Queue", resources.emailQueueName, expected.emailQueueName],
    ["email DLQ", resources.emailDeadLetterQueueName, expected.emailDeadLetterQueueName],
  ]) {
    if (actual !== wanted) throw new Error(`${environment} ${label} must be ${wanted}`)
  }
  if (resources.migrationsDirectory !== "migrations") {
    throw new Error(`${environment} D1 migrations_dir must be migrations`)
  }

  for (const [label, value] of [
    ["D1 database_name", resources.databaseName],
    ["audit Queue", resources.queueName],
    ["audit DLQ", resources.deadLetterQueueName],
    ["email Queue", resources.emailQueueName],
    ["email DLQ", resources.emailDeadLetterQueueName],
  ]) {
    rejectPlaceholder(value, `${environment} ${label}`)
  }
  if (resources.queueName !== resources.consumerQueueName) {
    throw new Error(`${environment} audit producer and consumer Queue names do not match`)
  }
  if (resources.queueName === resources.deadLetterQueueName) {
    throw new Error(`${environment} audit Queue and DLQ must be different`)
  }
  if (resources.emailQueueName !== resources.emailConsumerQueueName) {
    throw new Error(`${environment} email producer and consumer Queue names do not match`)
  }
  if (resources.emailQueueName === resources.emailDeadLetterQueueName) {
    throw new Error(`${environment} email Queue and DLQ must be different`)
  }
  if (
    new Set([
      resources.queueName,
      resources.deadLetterQueueName,
      resources.emailQueueName,
      resources.emailDeadLetterQueueName,
    ]).size !== 4
  ) {
    throw new Error(`${environment} audit and email Queue/DLQ names must all be distinct`)
  }

  assertDistinct(resources.databaseId, otherResources.databaseId, "a D1 database")
  assertDistinct(resources.kvId, otherResources.kvId, "a KV namespace")
  assertDistinct(resources.queueName, otherResources.queueName, "an audit Queue")
  assertDistinct(resources.deadLetterQueueName, otherResources.deadLetterQueueName, "an audit DLQ")
  assertDistinct(resources.emailQueueName, otherResources.emailQueueName, "an email Queue")
  assertDistinct(
    resources.emailDeadLetterQueueName,
    otherResources.emailDeadLetterQueueName,
    "an email DLQ",
  )
  const durableObjects = new Map(
    (tables.get(`${prefix}.durable_objects.bindings`) ?? []).map((body) => [
      stringValue(body, "name"),
      stringValue(body, "class_name"),
    ]),
  )
  const missingDurableObjects = [...REQUIRED_DURABLE_OBJECTS].filter(
    ([name, className]) => durableObjects.get(name) !== className,
  )
  if (missingDurableObjects.length > 0) {
    throw new Error(
      `missing or incorrect Durable Object bindings: ${missingDurableObjects.map(([name]) => name).join(", ")}`,
    )
  }

  if (!/^\s*crons\s*=\s*\[\s*"15 \* \* \* \*"\s*]\s*$/m.test(trigger)) {
    throw new Error(`${environment} maintenance cron must run hourly at minute 15`)
  }
}

function main() {
  const environment = process.argv[2]
  const configPath = resolve(process.env.WRANGLER_CONFIG_PATH ?? "wrangler.toml")
  try {
    validateDeployConfig(readFileSync(configPath, "utf8"), environment)
    console.log(`Deployment configuration is valid for ${environment}.`)
  } catch (error) {
    console.error(`Deployment configuration is invalid: ${error instanceof Error ? error.message : error}`)
    process.exitCode = 1
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main()
