import { env, SELF } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { verifyUserPassword } from "../../src/auth/password"
import { countUsers, getUserByEmail, getUserGroupNames } from "../../src/db/queries/users"

const ISSUER = "https://auth.pangda.app"
const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-more-than-32-characters"

function bootstrap(email: string, token = BOOTSTRAP_TOKEN): Promise<Response> {
  return SELF.fetch(`${ISSUER}/setup/bootstrap`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-bootstrap-token": token,
    },
    body: JSON.stringify({
      email,
      name: "Initial Owner",
      password: "bootstrap password is long enough",
    }),
  })
}

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM password_credentials"),
    env.DB.prepare("DELETE FROM user_groups"),
    env.DB.prepare("DELETE FROM users"),
    env.DB.prepare("DELETE FROM bootstrap_state"),
  ])
  await env.RATE_LIMIT.getByName("bootstrap:unknown").reset()
})

describe("initial administrator bootstrap", () => {
  it("requires the bootstrap secret and permanently closes after one success", async () => {
    expect((await bootstrap("owner@pangda.app", "wrong-token")).status).toBe(404)
    const created = await bootstrap("owner@pangda.app")
    expect(created.status).toBe(201)
    expect((await bootstrap("second@pangda.app")).status).toBe(409)

    const owner = await getUserByEmail(env, "owner@pangda.app")
    expect(owner).not.toBeNull()
    if (owner === null) return
    expect(await getUserGroupNames(env, owner.id)).toEqual(
      expect.arrayContaining(["admins", "employees"]),
    )
    expect(await verifyUserPassword(env, owner.id, "bootstrap password is long enough")).toBe(true)
  })

  it("atomically allows only one of two concurrent bootstrap attempts", async () => {
    const responses = await Promise.all([
      bootstrap("race-one@pangda.app"),
      bootstrap("race-two@pangda.app"),
    ])
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409])
    expect(await countUsers(env)).toBe(1)
    expect(
      (
        await env.DB.prepare(
          `SELECT COUNT(*) AS n FROM user_groups ug
           JOIN groups g ON g.id = ug.group_id WHERE g.name = 'admins'`,
        ).first<{ n: number }>()
      )?.n,
    ).toBe(1)
  })
})
