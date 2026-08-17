import * as z from "zod"
import {
  type EffectivePermissionRule,
  listPermissionRuleReferences,
  type PermissionGroupRule,
  type PermissionGroupRuleInput,
  type PermissionRuleCondition,
  permissionRuleConditionSchema,
  validatePermissionGroupRules,
} from "../../oauth/permission-rules"
import { generateId, ID_PREFIX } from "../../utils/id"
import { nowSeconds } from "../../utils/time"

export type PermissionGroupPolicy = {
  readonly priority: number
  readonly rules: readonly PermissionGroupRule[]
}

export type ReplacePermissionGroupRulesResult =
  | "updated"
  | "not_found"
  | "invalid_rule"
  | "invalid_application"
  | "invalid_api"
  | "invalid_scope"
  | "standard_scope"

const groupPolicyRowSchema = z.object({ priority: z.number() })
const ruleRowSchema = z.object({
  id: z.string(),
  effect: z.enum(["allow", "deny"]),
  condition_json: z.string(),
})
const effectiveRuleRowSchema = z.object({
  group_id: z.string(),
  group_name: z.string(),
  priority: z.number(),
  rule_id: z.string().nullable(),
  effect: z.enum(["allow", "deny"]).nullable(),
  condition_json: z.string().nullable(),
})
function parseCondition(raw: string): PermissionRuleCondition | null {
  try {
    const parsed = permissionRuleConditionSchema.safeParse(JSON.parse(raw))
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

export async function getPermissionGroupPolicy(
  env: Env,
  groupId: string,
): Promise<PermissionGroupPolicy | null> {
  const [groupResult, ruleResult] = await env.DB.batch([
    env.DB.prepare("SELECT priority FROM groups WHERE id = ?").bind(groupId),
    env.DB.prepare(
      `SELECT id, effect, condition_json
       FROM permission_group_rules
       WHERE group_id = ?
       ORDER BY position, id`,
    ).bind(groupId),
  ])
  if (groupResult === undefined || ruleResult === undefined) return null
  const groupRows = z.array(groupPolicyRowSchema).safeParse(groupResult.results)
  if (!groupRows.success || groupRows.data.length !== 1) return null
  const rows = z.array(ruleRowSchema).parse(ruleResult.results)
  const rules: PermissionGroupRule[] = []
  for (const row of rows) {
    const condition = parseCondition(row.condition_json)
    if (condition === null) continue
    rules.push({ id: row.id, effect: row.effect, condition })
  }
  return { priority: groupRows.data[0]?.priority ?? 0, rules }
}

async function validateRuleReferences(
  env: Env,
  rules: readonly PermissionGroupRuleInput[],
): Promise<"valid" | "invalid_application" | "invalid_api" | "invalid_scope"> {
  const matches = rules.flatMap((rule) => listPermissionRuleReferences(rule.condition))
  const applicationIds = [
    ...new Set(
      matches.filter((match) => match.field === "application").map((match) => match.value),
    ),
  ]
  const apiUris = [
    ...new Set(matches.filter((match) => match.field === "api").map((match) => match.value)),
  ]
  const scopes = [
    ...new Set(matches.filter((match) => match.field === "scope").map((match) => match.value)),
  ]
  const [applicationResult, apiResult, scopeResult] = await env.DB.batch([
    env.DB.prepare(
      `SELECT client_id
       FROM oauth_clients
       WHERE client_kind IN ('application', 'device')
         AND client_id IN (SELECT CAST(value AS TEXT) FROM json_each(?))`,
    ).bind(JSON.stringify(applicationIds)),
    env.DB.prepare(
      `SELECT resource_uri
       FROM oauth_resources
       WHERE resource_uri IN (SELECT CAST(value AS TEXT) FROM json_each(?))`,
    ).bind(JSON.stringify(apiUris)),
    env.DB.prepare(
      `SELECT DISTINCT CAST(offered.value AS TEXT) AS scope
       FROM oauth_resources AS resource
       JOIN json_each(resource.allowed_scopes_json) AS offered
       WHERE CAST(offered.value AS TEXT)
         IN (SELECT CAST(value AS TEXT) FROM json_each(?))`,
    ).bind(JSON.stringify(scopes)),
  ])
  if (applicationResult === undefined) return "invalid_application"
  if (apiResult === undefined) return "invalid_api"
  if (scopeResult === undefined) return "invalid_scope"
  if (applicationResult.results.length !== applicationIds.length) return "invalid_application"
  if (apiResult.results.length !== apiUris.length) return "invalid_api"
  if (scopeResult.results.length !== scopes.length) return "invalid_scope"
  return "valid"
}

export async function replacePermissionGroupRules(
  env: Env,
  groupId: string,
  rawRules: unknown,
): Promise<ReplacePermissionGroupRulesResult> {
  const validation = validatePermissionGroupRules(rawRules)
  if (!validation.ok) {
    return validation.issue === "standard_scope" ? "standard_scope" : "invalid_rule"
  }
  const [groupRow, existingResult] = await Promise.all([
    env.DB.prepare("SELECT id FROM groups WHERE id = ?").bind(groupId).first(),
    env.DB.prepare("SELECT id FROM permission_group_rules WHERE group_id = ?")
      .bind(groupId)
      .all<{ id: string }>(),
  ])
  if (groupRow === null) return "not_found"
  const existingIds = new Set(existingResult.results.map((row) => row.id))
  if (validation.rules.some((rule) => rule.id !== undefined && !existingIds.has(rule.id))) {
    return "invalid_rule"
  }
  const referenceResult = await validateRuleReferences(env, validation.rules)
  if (referenceResult !== "valid") return referenceResult

  const now = nowSeconds()
  const rules = validation.rules.map((rule) => ({
    id: rule.id ?? generateId(ID_PREFIX.permissionRule),
    effect: rule.effect,
    condition: rule.condition,
  }))
  await env.DB.batch([
    env.DB.prepare("DELETE FROM permission_group_rules WHERE group_id = ?").bind(groupId),
    env.DB.prepare(
      `INSERT INTO permission_group_rules
         (id, group_id, effect, condition_json, position, created_at, updated_at)
       SELECT
         CAST(json_extract(value, '$.id') AS TEXT),
         ?,
         CAST(json_extract(value, '$.effect') AS TEXT),
         json_extract(value, '$.condition'),
         CAST(key AS INTEGER),
         ?,
         ?
       FROM json_each(?)`,
    ).bind(groupId, now, now, JSON.stringify(rules)),
  ])
  return "updated"
}

export type UserPermissionRules = {
  readonly valid: boolean
  readonly adminMember: boolean
  readonly rules: readonly EffectivePermissionRule[]
}

/** Load every rule attached to the user's current memberships in one D1 read. */
export async function getUserPermissionRules(
  env: Env,
  userId: string,
): Promise<UserPermissionRules> {
  const result = await env.DB.prepare(
    `SELECT
       permission_group.id AS group_id,
       permission_group.name AS group_name,
       permission_group.priority,
       policy.id AS rule_id,
       policy.effect,
       policy.condition_json
     FROM user_groups AS membership
     JOIN groups AS permission_group ON permission_group.id = membership.group_id
     LEFT JOIN permission_group_rules AS policy ON policy.group_id = permission_group.id
     WHERE membership.user_id = ?
     ORDER BY permission_group.priority ASC, permission_group.id, policy.position, policy.id`,
  )
    .bind(userId)
    .all()
  const parsed = z.array(effectiveRuleRowSchema).safeParse(result.results)
  if (!parsed.success) return { valid: false, adminMember: false, rules: [] }
  const rules: EffectivePermissionRule[] = []
  let adminMember = false
  for (const row of parsed.data) {
    adminMember = adminMember || row.group_name === "admins"
    if (row.rule_id === null || row.effect === null || row.condition_json === null) continue
    const condition = parseCondition(row.condition_json)
    if (condition === null) return { valid: false, adminMember, rules: [] }
    const validation = validatePermissionGroupRules([{ effect: row.effect, condition }])
    if (!validation.ok) return { valid: false, adminMember, rules: [] }
    rules.push({
      id: row.rule_id,
      groupId: row.group_id,
      groupName: row.group_name,
      priority: row.priority,
      effect: row.effect,
      condition,
    })
  }
  return { valid: true, adminMember, rules }
}
