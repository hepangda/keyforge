import * as z from "zod"
import { RESOURCE_AUTHORIZED_SCOPES } from "./scope-policy"

export const PERMISSION_GROUP_PRIORITIES = {
  minimum: 0,
  maximum: 1_000_000,
} as const

export const MAX_PERMISSION_GROUP_RULES = 256
export const MAX_PERMISSION_RULE_DEPTH = 5
export const MAX_PERMISSION_RULE_NODES = 64
export const MAX_PERMISSION_RULE_CHILDREN = 16
export const MAX_PERMISSION_RULE_SET_VALUES = 64

export const PERMISSION_RULE_EFFECTS = ["allow", "deny"] as const
export type PermissionRuleEffect = (typeof PERMISSION_RULE_EFFECTS)[number]

export const PERMISSION_RULE_FIELDS = ["application", "api", "scope"] as const
export type PermissionRuleField = (typeof PERMISSION_RULE_FIELDS)[number]

export const PERMISSION_RULE_SINGLE_OPERATORS = ["equals", "not_equals"] as const
export type PermissionRuleSingleOperator = (typeof PERMISSION_RULE_SINGLE_OPERATORS)[number]

export const PERMISSION_RULE_SET_OPERATORS = ["in", "not_in"] as const
export type PermissionRuleSetOperator = (typeof PERMISSION_RULE_SET_OPERATORS)[number]

export type PermissionRuleSingleMatchCondition = {
  readonly field: PermissionRuleField
  readonly operator: PermissionRuleSingleOperator
  readonly value: string
}

export type PermissionRuleSetMatchCondition = {
  readonly field: PermissionRuleField
  readonly operator: PermissionRuleSetOperator
  readonly values: readonly string[]
}

export type PermissionRuleMatchCondition =
  | PermissionRuleSingleMatchCondition
  | PermissionRuleSetMatchCondition

export type PermissionRuleGroupCondition = {
  readonly operator: "and" | "or"
  readonly conditions: readonly PermissionRuleCondition[]
}

export type PermissionRuleCondition = PermissionRuleMatchCondition | PermissionRuleGroupCondition

export type PermissionGroupRule = {
  readonly id: string
  readonly effect: PermissionRuleEffect
  readonly condition: PermissionRuleCondition
}

export type PermissionGroupRuleInput = {
  readonly id?: string
  readonly effect: PermissionRuleEffect
  readonly condition: PermissionRuleCondition
}

export type EffectivePermissionRule = PermissionGroupRule & {
  readonly groupId: string
  readonly groupName: string
  readonly priority: number
}

export type PermissionRuleContext = {
  readonly application: string
  readonly api: string
  readonly scope: string
}

export type PermissionRuleValidationIssue =
  | "invalid_rule"
  | "too_many_rules"
  | "duplicate_rule_id"
  | "standard_scope"

export type PermissionRuleValidation =
  | { readonly ok: true; readonly rules: readonly PermissionGroupRuleInput[] }
  | { readonly ok: false; readonly issue: PermissionRuleValidationIssue }

const standardScopeSet: ReadonlySet<string> = new Set(RESOURCE_AUTHORIZED_SCOPES)

const ruleValueSchema = z.string().min(1).max(2048)

const singleMatchConditionSchema = z
  .object({
    field: z.enum(PERMISSION_RULE_FIELDS),
    operator: z.enum(PERMISSION_RULE_SINGLE_OPERATORS),
    value: ruleValueSchema,
  })
  .strict()

const setMatchConditionSchema = z
  .object({
    field: z.enum(PERMISSION_RULE_FIELDS),
    operator: z.enum(PERMISSION_RULE_SET_OPERATORS),
    values: z
      .array(ruleValueSchema)
      .min(1)
      .max(MAX_PERMISSION_RULE_SET_VALUES)
      .refine((values) => new Set(values).size === values.length),
  })
  .strict()

export const permissionRuleConditionSchema: z.ZodType<PermissionRuleCondition> = z.lazy(() =>
  z.union([
    singleMatchConditionSchema,
    setMatchConditionSchema,
    z
      .object({
        operator: z.enum(["and", "or"]),
        conditions: z.array(permissionRuleConditionSchema).min(1).max(MAX_PERMISSION_RULE_CHILDREN),
      })
      .strict(),
  ]),
)

const ruleInputSchema = z
  .object({
    id: z.string().min(1).max(128).optional(),
    effect: z.enum(PERMISSION_RULE_EFFECTS),
    condition: permissionRuleConditionSchema,
  })
  .strict()

export const permissionGroupRulesInputSchema = z
  .array(ruleInputSchema)
  .max(MAX_PERMISSION_GROUP_RULES)

function inspectCondition(
  condition: PermissionRuleCondition,
  depth: number,
): { readonly nodes: number; readonly valid: boolean; readonly standardScope: boolean } {
  if (depth > MAX_PERMISSION_RULE_DEPTH) {
    return { nodes: 1, valid: false, standardScope: false }
  }
  if ("field" in condition) {
    const values = "value" in condition ? [condition.value] : condition.values
    return {
      nodes: 1,
      valid: true,
      standardScope:
        condition.field === "scope" && values.some((value) => standardScopeSet.has(value)),
    }
  }
  let nodes = 1
  let valid = condition.conditions.length > 0
  let standardScope = false
  for (const child of condition.conditions) {
    const inspected = inspectCondition(child, depth + 1)
    nodes += inspected.nodes
    valid = valid && inspected.valid
    standardScope = standardScope || inspected.standardScope
  }
  return { nodes, valid: valid && nodes <= MAX_PERMISSION_RULE_NODES, standardScope }
}

export function validatePermissionGroupRules(raw: unknown): PermissionRuleValidation {
  const parsed = permissionGroupRulesInputSchema.safeParse(raw)
  if (!parsed.success) {
    return {
      ok: false,
      issue:
        Array.isArray(raw) && raw.length > MAX_PERMISSION_GROUP_RULES
          ? "too_many_rules"
          : "invalid_rule",
    }
  }
  const ids = parsed.data.flatMap((rule) => (rule.id === undefined ? [] : [rule.id]))
  if (new Set(ids).size !== ids.length) return { ok: false, issue: "duplicate_rule_id" }
  for (const rule of parsed.data) {
    const inspected = inspectCondition(rule.condition, 1)
    if (!inspected.valid || inspected.nodes > MAX_PERMISSION_RULE_NODES) {
      return { ok: false, issue: "invalid_rule" }
    }
    if (inspected.standardScope) return { ok: false, issue: "standard_scope" }
  }
  return {
    ok: true,
    rules: parsed.data.map((rule) =>
      rule.id === undefined
        ? { effect: rule.effect, condition: rule.condition }
        : { id: rule.id, effect: rule.effect, condition: rule.condition },
    ),
  }
}

export function conditionUsesScope(condition: PermissionRuleCondition): boolean {
  if ("field" in condition) return condition.field === "scope"
  return condition.conditions.some(conditionUsesScope)
}

export function listPermissionRuleMatches(
  condition: PermissionRuleCondition,
): readonly PermissionRuleMatchCondition[] {
  if ("field" in condition) return [condition]
  return condition.conditions.flatMap(listPermissionRuleMatches)
}

export type PermissionRuleReference = {
  readonly field: PermissionRuleField
  readonly value: string
}

export function listPermissionRuleReferences(
  condition: PermissionRuleCondition,
): readonly PermissionRuleReference[] {
  if (!("field" in condition)) return condition.conditions.flatMap(listPermissionRuleReferences)
  return ("value" in condition ? [condition.value] : condition.values).map((value) => ({
    field: condition.field,
    value,
  }))
}

export function permissionRuleMatches(
  condition: PermissionRuleCondition,
  context: PermissionRuleContext,
): boolean {
  if ("field" in condition) {
    const actual = context[condition.field]
    switch (condition.operator) {
      case "equals":
        return actual === condition.value
      case "not_equals":
        return actual !== condition.value
      case "in":
        return condition.values.includes(actual)
      case "not_in":
        return !condition.values.includes(actual)
    }
  }
  return condition.operator === "and"
    ? condition.conditions.every((child) => permissionRuleMatches(child, context))
    : condition.conditions.some((child) => permissionRuleMatches(child, context))
}

export type PermissionRuleDecision =
  | { readonly allowed: true; readonly priority: number }
  | { readonly allowed: false; readonly reason: "no_match" | "denied"; readonly priority?: number }

/** Resolve matching rules at the smallest (nice-style) priority; deny wins ties. */
export function resolvePermissionRules(
  rules: readonly EffectivePermissionRule[],
  context: PermissionRuleContext,
  stage: "base" | "scope",
): PermissionRuleDecision {
  const matching = rules.filter(
    (rule) =>
      conditionUsesScope(rule.condition) === (stage === "scope") &&
      permissionRuleMatches(rule.condition, context),
  )
  if (matching.length === 0) return { allowed: false, reason: "no_match" }
  const priority = Math.min(...matching.map((rule) => rule.priority))
  const winning = matching.filter((rule) => rule.priority === priority)
  return winning.some((rule) => rule.effect === "deny")
    ? { allowed: false, reason: "denied", priority }
    : { allowed: true, priority }
}

export function isResourceAuthorizedScope(scope: string): boolean {
  return standardScopeSet.has(scope)
}
