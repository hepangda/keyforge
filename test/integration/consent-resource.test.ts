import { env } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import { getConsent, listConsentsByUser, saveConsent } from "../../src/db/queries/consents"
import { createUser } from "../../src/db/queries/users"
import { consentCoversScopes } from "../../src/oauth/consent"

const CLIENT = "pangda_app"
const API_RESOURCE = "https://api.pangda.app"
const APP_RESOURCE = "https://app.pangda.app"

let userId = ""

beforeEach(async () => {
  await env.DB.batch([env.DB.prepare("DELETE FROM consents"), env.DB.prepare("DELETE FROM users")])
  const user = await createUser(env, { email: "consent@pangda.app" })
  userId = user.id
})

describe("resource-bound consent", () => {
  it("stores independent grants for the same user and client per resource", async () => {
    await saveConsent(env, {
      userId,
      clientId: CLIENT,
      resource: API_RESOURCE,
      scope: "openid api.read",
    })
    await saveConsent(env, {
      userId,
      clientId: CLIENT,
      resource: APP_RESOURCE,
      scope: "openid app.read",
    })

    expect((await getConsent(env, userId, CLIENT, API_RESOURCE))?.scope).toBe("openid api.read")
    expect((await getConsent(env, userId, CLIENT, APP_RESOURCE))?.scope).toBe("openid app.read")
    expect(await listConsentsByUser(env, userId)).toHaveLength(2)
  })

  it("never applies consent from one resource to another", async () => {
    await saveConsent(env, {
      userId,
      clientId: CLIENT,
      resource: API_RESOURCE,
      scope: "openid api.read",
    })

    expect(await consentCoversScopes(env, userId, CLIENT, API_RESOURCE, ["openid"])).toBe(true)
    expect(await consentCoversScopes(env, userId, CLIENT, APP_RESOURCE, ["openid"])).toBe(false)
  })

  it("updates scopes only within the matching resource grant", async () => {
    await saveConsent(env, {
      userId,
      clientId: CLIENT,
      resource: API_RESOURCE,
      scope: "openid",
    })
    await saveConsent(env, {
      userId,
      clientId: CLIENT,
      resource: API_RESOURCE,
      scope: "openid api.read",
    })

    expect(await listConsentsByUser(env, userId)).toHaveLength(1)
    expect((await getConsent(env, userId, CLIENT, API_RESOURCE))?.scope).toBe("openid api.read")
  })
})
