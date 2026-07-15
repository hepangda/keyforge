import { Hono } from "hono"
import { z } from "zod"
import {
  ALIAS_PATTERN,
  countUsersInGroup,
  getGroupByName,
  getUserByAlias,
  getUserByEmail,
  MAX_ALIAS_LENGTH,
} from "../db/queries/users"
import { recordAudit } from "../security/audit"
import { hashPassword, timingSafeEqualString } from "../security/crypto"
import { checkRateLimit } from "../security/rate-limit"
import { clientIpHash } from "../security/request-meta"
import type { AppBindings } from "../types/app"
import { readJsonBody } from "../utils/http"
import { generateId, ID_PREFIX } from "../utils/id"
import { nowSeconds } from "../utils/time"

export const bootstrap = new Hono<AppBindings>()

const bootstrapSchema = z.object({
  email: z.email(),
  alias: z.string().min(1).max(MAX_ALIAS_LENGTH).regex(ALIAS_PATTERN).optional(),
  name: z.string().min(1).max(120),
  password: z.string().min(16).max(128),
})

bootstrap.post("/setup/bootstrap", async (c) => {
  const ipHash = await clientIpHash(c)
  const rate = await checkRateLimit(c.env, `bootstrap:${ipHash ?? "unknown"}`, 5, 15 * 60)
  if (!rate.allowed) {
    c.header("retry-after", String(rate.retryAfterSeconds))
    return c.json({ error: "rate_limited" }, 429)
  }
  const configured = c.env.BOOTSTRAP_TOKEN
  const presented = c.req.header("x-bootstrap-token")
  if (
    configured === undefined ||
    configured.length < 32 ||
    presented === undefined ||
    !timingSafeEqualString(configured, presented)
  ) {
    return c.json({ error: "not_found" }, 404)
  }
  if ((await countUsersInGroup(c.env, "admins")) > 0) {
    return c.json({ error: "bootstrap_already_completed" }, 409)
  }
  const parsed = bootstrapSchema.safeParse(await readJsonBody(c))
  if (!parsed.success) {
    return c.json({ error: "invalid_request" }, 400)
  }
  const email = parsed.data.email.trim().toLowerCase()
  if ((await getUserByEmail(c.env, email)) !== null) {
    return c.json({ error: "email_in_use" }, 409)
  }
  const [admins, employees] = await Promise.all([
    getGroupByName(c.env, "admins"),
    getGroupByName(c.env, "employees"),
  ])
  if (admins === null) {
    return c.json({ error: "bootstrap_unavailable" }, 503)
  }
  const userId = generateId(ID_PREFIX.user)
  const generatedAlias =
    email
      .split("@", 1)[0]
      ?.replace(/[^A-Za-z0-9]/g, "")
      .slice(0, 48) || "admin"
  const alias = parsed.data.alias ?? `${generatedAlias}${userId.slice(-8)}`
  if ((await getUserByAlias(c.env, alias)) !== null) {
    return c.json({ error: "alias_in_use" }, 409)
  }
  const now = nowSeconds()
  const passwordHash = await hashPassword(parsed.data.password)
  const passwordId = generateId(ID_PREFIX.password)
  const statements = [
    c.env.DB.prepare(
      "INSERT INTO bootstrap_state (id, completed_at, user_id) VALUES (1, ?, ?)",
    ).bind(now, userId),
    c.env.DB.prepare(
      `INSERT INTO users
         (id, email, alias, email_verified, name, disabled, created_at, updated_at)
       VALUES (?, ?, ?, 0, ?, 0, ?, ?)`,
    ).bind(userId, email, alias, parsed.data.name, now, now),
    c.env.DB.prepare(
      `INSERT INTO password_credentials
         (id, user_id, password_hash, name, admin_eligible, created_at, updated_at)
       VALUES (?, ?, ?, 'Primary password', 1, ?, ?)`,
    ).bind(passwordId, userId, passwordHash, now, now),
    c.env.DB.prepare(
      "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, ?, ?)",
    ).bind(userId, admins.id, now),
  ]
  if (employees !== null && employees.id !== admins.id) {
    statements.push(
      c.env.DB.prepare(
        "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, ?, ?)",
      ).bind(userId, employees.id, now),
    )
  }
  try {
    // D1 batches commit as one transaction. The singleton claim is first, so
    // concurrent bootstrap attempts cannot both create an administrator.
    await c.env.DB.batch(statements)
  } catch (error) {
    console.error("bootstrap.atomic_create_failed", c.get("requestId"), error)
    return c.json({ error: "bootstrap_already_completed" }, 409)
  }
  await recordAudit(c.env, {
    type: "admin.user.created",
    userId,
    requestId: c.get("requestId"),
    ipHash,
    success: true,
    detail: "initial administrator bootstrapped",
  })
  return c.json({ user_id: userId, email, alias }, 201)
})
