import { env } from "cloudflare:test"
import { beforeEach, describe, expect, it } from "vitest"
import type { SocialProfile } from "../../src/auth/account-linking"
import { resolveSocialLogin } from "../../src/auth/account-linking"
import { createUser, getUserById } from "../../src/db/queries/users"

function profile(overrides: Partial<SocialProfile> = {}): SocialProfile {
  return {
    provider: "github",
    providerUserId: "gh-12345",
    email: "octo@pangda.app",
    emailVerified: true,
    name: "Octo Cat",
    picture: "https://example.com/a.png",
    ...overrides,
  }
}

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM identities"),
    env.DB.prepare("DELETE FROM users"),
  ])
})

describe("resolveSocialLogin", () => {
  it("creates a new account when there is no identity or email conflict", async () => {
    const outcome = await resolveSocialLogin(env, profile({ email: "new@pangda.app" }), null, true)
    expect(outcome.kind).toBe("created")
    if (outcome.kind === "created") {
      expect((await getUserById(env, outcome.userId))?.email).toBe("new@pangda.app")
    }
  })

  it("logs in an existing identity on repeat login", async () => {
    const first = await resolveSocialLogin(env, profile({ email: "repeat@pangda.app" }), null, true)
    const second = await resolveSocialLogin(
      env,
      profile({ email: "repeat@pangda.app" }),
      null,
      true,
    )
    expect(second.kind).toBe("login")
    if (first.kind === "created" && second.kind === "login") {
      expect(second.userId).toBe(first.userId)
    }
  })

  it("links to the currently signed-in user", async () => {
    const user = await createUser(env, { email: "me@pangda.app", userType: "internal" })
    const outcome = await resolveSocialLogin(
      env,
      profile({ providerUserId: "gh-999", email: "other@example.com" }),
      user.id,
      true,
    )
    expect(outcome.kind).toBe("linked")
    if (outcome.kind === "linked") {
      expect(outcome.userId).toBe(user.id)
    }
  })

  it("never switches accounts when a signed-in user links an identity owned elsewhere", async () => {
    const owner = await resolveSocialLogin(env, profile({ email: "owner@pangda.app" }), null, true)
    const current = await createUser(env, { email: "current@pangda.app", userType: "internal" })
    const outcome = await resolveSocialLogin(
      env,
      profile({ email: "owner@pangda.app" }),
      current.id,
      true,
    )
    expect(owner.kind).toBe("created")
    expect(outcome.kind).toBe("conflict")
  })

  it("allows at most one identity per provider on an account", async () => {
    const current = await createUser(env, { email: "current@pangda.app", userType: "internal" })
    expect(
      (await resolveSocialLogin(env, profile({ providerUserId: "first" }), current.id, true)).kind,
    ).toBe("linked")
    expect(
      (await resolveSocialLogin(env, profile({ providerUserId: "second" }), current.id, true)).kind,
    ).toBe("conflict")
  })

  it("requires explicit binding when a verified email matches a local account (signed out)", async () => {
    await createUser(env, { email: "existing@pangda.app", userType: "internal" })
    const outcome = await resolveSocialLogin(
      env,
      profile({ providerUserId: "gh-777", email: "existing@pangda.app" }),
      null,
      true,
    )
    expect(outcome.kind).toBe("binding_required")
  })

  it("never takes over a local account by email (no identity is linked)", async () => {
    const victim = await createUser(env, { email: "victim@pangda.app", userType: "internal" })
    const outcome = await resolveSocialLogin(
      env,
      profile({ providerUserId: "gh-attacker", email: "victim@pangda.app", emailVerified: true }),
      null,
      true,
    )
    expect(outcome.kind).toBe("binding_required")
    const linked = await env.DB.prepare("SELECT COUNT(*) AS n FROM identities WHERE user_id = ?")
      .bind(victim.id)
      .first<{ n: number }>()
    expect(linked?.n).toBe(0)
  })
})
