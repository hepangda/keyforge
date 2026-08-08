import { env } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import {
  createUser,
  getUserGroupIds,
  MAX_USER_GROUPS,
  setUserGroups,
  setUserGroupsPreservingActiveAdmin,
} from "../../src/db/queries/users"

let userId = ""
const groupIds = Array.from(
  { length: MAX_USER_GROUPS },
  (_, index) => `grp_test_bulk_${String(index).padStart(3, "0")}`,
)

beforeEach(async () => {
  await env.DB.prepare("DELETE FROM users WHERE email = 'group-limit@example.test'").run()
  await env.DB.prepare("DELETE FROM groups WHERE name LIKE 'test-bulk-%'").run()
  await env.DB.prepare(
    `WITH RECURSIVE sequence(n) AS (
       SELECT 0
       UNION ALL
       SELECT n + 1 FROM sequence WHERE n < ?
     )
     INSERT INTO groups (id, name, description, created_at)
     SELECT printf('grp_test_bulk_%03d', n), printf('test-bulk-%03d', n), NULL, unixepoch()
     FROM sequence`,
  )
    .bind(MAX_USER_GROUPS - 1)
    .run()
  userId = (
    await createUser(env, {
      email: "group-limit@example.test",
      name: "Group Limit",
    })
  ).id
})

function instrumentDatabase(base: Env): {
  readonly wrapped: Env
  readonly metrics: { prepareCount: number; maxBindings: number }
} {
  const metrics = { prepareCount: 0, maxBindings: 0 }
  const database = new Proxy(base.DB, {
    get(target, property) {
      if (property === "prepare") {
        return (sql: string) => {
          metrics.prepareCount += 1
          const statement = target.prepare(sql)
          return new Proxy(statement, {
            get(statementTarget, statementProperty) {
              if (statementProperty === "bind") {
                return (...values: unknown[]) => {
                  metrics.maxBindings = Math.max(metrics.maxBindings, values.length)
                  return statementTarget.bind(...values)
                }
              }
              const value = Reflect.get(statementTarget, statementProperty)
              return typeof value === "function" ? value.bind(statementTarget) : value
            },
          })
        }
      }
      const value = Reflect.get(target, property)
      return typeof value === "function" ? value.bind(target) : value
    },
  })
  const wrapped = new Proxy(base, {
    get(target, property) {
      return property === "DB" ? database : Reflect.get(target, property)
    },
  })
  return { wrapped, metrics }
}

describe("bounded user-group replacement", () => {
  it("assigns 50 groups with fixed-size membership and revocation statements", async () => {
    const { wrapped, metrics } = instrumentDatabase(env)

    await setUserGroups(wrapped, userId, groupIds.slice(0, 50))

    expect(await getUserGroupIds(env, userId)).toHaveLength(50)
    expect(metrics.prepareCount).toBe(5)
    expect(metrics.maxBindings).toBe(4)
  })

  it("atomically assigns the full 100-group limit with fixed-size bindings", async () => {
    const { wrapped, metrics } = instrumentDatabase(env)

    expect(await setUserGroupsPreservingActiveAdmin(wrapped, userId, groupIds)).toBe(true)

    expect(await getUserGroupIds(env, userId)).toEqual(groupIds)
    expect(metrics.prepareCount).toBe(6)
    expect(metrics.maxBindings).toBe(4)
  })

  it("rejects more than the shared group limit before preparing D1 statements", async () => {
    const tooMany = [...groupIds, "grp_test_bulk_100"]
    const { wrapped, metrics } = instrumentDatabase(env)

    await expect(setUserGroups(wrapped, userId, tooMany)).rejects.toThrow(RangeError)
    await expect(setUserGroupsPreservingActiveAdmin(wrapped, userId, tooMany)).rejects.toThrow(
      RangeError,
    )
    expect(metrics.prepareCount).toBe(0)
  })
})
