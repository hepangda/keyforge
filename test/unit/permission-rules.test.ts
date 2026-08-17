import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import {
  type EffectivePermissionRule,
  listPermissionRuleReferences,
  MAX_PERMISSION_RULE_SET_VALUES,
  permissionRuleMatches,
  resolvePermissionRules,
  validatePermissionGroupRules,
} from "../../src/oauth/permission-rules"

const baseContext = {
  application: "app-a",
  api: "https://api.example.test",
  scope: "api.read",
}

function rule(
  id: string,
  priority: number,
  effect: "allow" | "deny",
  field: "application" | "api" | "scope",
  value: string,
): EffectivePermissionRule {
  return {
    id,
    groupId: `group-${id}`,
    groupName: `group-${id}`,
    priority,
    effect,
    condition: { field, operator: "equals", value },
  }
}

describe("permission rule engine", () => {
  it("evaluates nested and/or conditions", () => {
    expect(
      permissionRuleMatches(
        {
          operator: "and",
          conditions: [
            { field: "application", operator: "equals", value: "app-a" },
            {
              operator: "or",
              conditions: [
                { field: "scope", operator: "equals", value: "api.write" },
                { field: "scope", operator: "equals", value: "api.read" },
              ],
            },
          ],
        },
        baseContext,
      ),
    ).toBe(true)
  })

  it("evaluates equality, inequality, inclusion, and exclusion operators", () => {
    expect(
      permissionRuleMatches(
        { field: "application", operator: "not_equals", value: "app-b" },
        baseContext,
      ),
    ).toBe(true)
    expect(
      permissionRuleMatches(
        { field: "api", operator: "in", values: ["urn:other", "https://api.example.test"] },
        baseContext,
      ),
    ).toBe(true)
    expect(
      permissionRuleMatches(
        { field: "scope", operator: "not_in", values: ["api.write", "api.delete"] },
        baseContext,
      ),
    ).toBe(true)
    expect(
      permissionRuleMatches(
        { field: "scope", operator: "not_in", values: ["api.read", "api.write"] },
        baseContext,
      ),
    ).toBe(false)
  })

  it("expands every set member for catalog-reference validation", () => {
    expect(
      listPermissionRuleReferences({
        field: "application",
        operator: "in",
        values: ["app-a", "app-b"],
      }),
    ).toEqual([
      { field: "application", value: "app-a" },
      { field: "application", value: "app-b" },
    ])
  })

  it("requires strict, non-empty, unique, bounded set operands", () => {
    for (const condition of [
      { field: "api", operator: "in", values: [] },
      { field: "api", operator: "not_in", values: ["urn:a", "urn:a"] },
      { field: "api", operator: "in", value: "urn:a" },
      { field: "api", operator: "equals", values: ["urn:a"] },
      {
        field: "api",
        operator: "in",
        values: Array.from({ length: MAX_PERMISSION_RULE_SET_VALUES + 1 }, (_, index) =>
          String(index),
        ),
      },
    ]) {
      expect(validatePermissionGroupRules([{ effect: "allow", condition }])).toEqual({
        ok: false,
        issue: "invalid_rule",
      })
    }
  })

  it("uses nice semantics where the smallest matching priority wins", () => {
    const decision = resolvePermissionRules(
      [
        rule("preferred-deny", 10, "deny", "application", "app-a"),
        rule("deprioritized-allow", 20, "allow", "api", "https://api.example.test"),
      ],
      baseContext,
      "base",
    )
    expect(decision).toEqual({ allowed: false, reason: "denied", priority: 10 })
  })

  it("lets deny win at the same priority", () => {
    const decision = resolvePermissionRules(
      [
        rule("allow", 20, "allow", "application", "app-a"),
        rule("deny", 20, "deny", "api", "https://api.example.test"),
      ],
      baseContext,
      "base",
    )
    expect(decision).toEqual({ allowed: false, reason: "denied", priority: 20 })
  })

  it("separates base rules from scope-bearing rules and defaults to deny", () => {
    const rules = [
      rule("base", 10, "allow", "application", "app-a"),
      rule("scope", 10, "allow", "scope", "api.read"),
    ]
    expect(resolvePermissionRules(rules, baseContext, "base").allowed).toBe(true)
    expect(resolvePermissionRules(rules, baseContext, "scope").allowed).toBe(true)
    expect(resolvePermissionRules(rules, { ...baseContext, scope: "api.write" }, "scope")).toEqual({
      allowed: false,
      reason: "no_match",
    })
  })

  it.each([
    "openid",
    "profile",
    "email",
    "offline_access",
  ])("rejects separately configurable standard scope %s", (scope) => {
    expect(
      validatePermissionGroupRules([
        {
          effect: "deny",
          condition: { field: "scope", operator: "equals", value: scope },
        },
      ]),
    ).toEqual({ ok: false, issue: "standard_scope" })
    expect(
      validatePermissionGroupRules([
        {
          effect: "deny",
          condition: { field: "scope", operator: "not_in", values: ["api.read", scope] },
        },
      ]),
    ).toEqual({ ok: false, issue: "standard_scope" })
  })

  it("enforces standard-scope protection for direct D1 writes", async () => {
    await expect(
      env.DB.prepare(
        `INSERT INTO permission_group_rules
           (id, group_id, effect, condition_json, position, created_at, updated_at)
         VALUES (
           'prule_test_direct_standard', 'grp_seed_employees', 'deny',
           '{"operator":"or","conditions":[{"field":"api","operator":"equals","value":"https://api.pangda.app"},{"field":"scope","operator":"equals","value":"email"}]}',
           (SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = 'grp_seed_employees'),
           unixepoch(), unixepoch()
         )`,
      ).run(),
    ).rejects.toThrow(/standard scope/)

    await expect(
      env.DB.prepare(
        `INSERT INTO permission_group_rules
           (id, group_id, effect, condition_json, position, created_at, updated_at)
         VALUES (
           'prule_test_direct_standard_set', 'grp_seed_employees', 'deny',
           '{"field":"scope","operator":"not_in","values":["api.read","email"]}',
           (SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = 'grp_seed_employees'),
           unixepoch(), unixepoch()
         )`,
      ).run(),
    ).rejects.toThrow(/standard scope/)

    await env.DB.prepare(
      `INSERT INTO permission_group_rules
         (id, group_id, effect, condition_json, position, created_at, updated_at)
       VALUES (
         'prule_test_direct_custom', 'grp_seed_employees', 'deny',
         '{"field":"scope","operator":"equals","value":"api.read"}',
         (SELECT MAX(position) + 1 FROM permission_group_rules WHERE group_id = 'grp_seed_employees'),
         unixepoch(), unixepoch()
       )`,
    ).run()
    await expect(
      env.DB.prepare(
        `UPDATE permission_group_rules
         SET condition_json = '{"field":"scope","operator":"equals","value":"profile"}'
         WHERE id = 'prule_test_direct_custom'`,
      ).run(),
    ).rejects.toThrow(/standard scope/)
  })
})
