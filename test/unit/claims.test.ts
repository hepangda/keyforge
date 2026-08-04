import { describe, expect, it } from "vitest"
import { buildUserClaims } from "../../src/oidc/claims"
import { asUserId, type User } from "../../src/types/domain"

const ENV = { ISSUER: "https://auth.pangda.app" } as unknown as Env

const user: User = {
  id: asUserId("usr_claims"),
  email: "claims@pangda.app",
  alias: "claimsuser",
  emailVerified: true,
  name: "Claims User",
  picture: null,
  avatarKey: null,
  avatarContentType: null,
  avatarUpdatedAt: null,
  disabled: false,
  createdAt: 1,
}

const AVATAR_KEY = `${"a".repeat(43)}.png`

describe("OIDC claim scope policy", () => {
  it("releases the username with profile while withholding groups", () => {
    const claims = buildUserClaims(ENV, user, ["employees"], ["openid", "profile"])
    expect(claims.groups).toBeUndefined()
    expect(claims.preferred_username).toBe("claimsuser")
  })

  it("releases groups only with the groups scope", () => {
    const claims = buildUserClaims(ENV, user, ["employees"], ["openid", "groups"])
    expect(claims.groups).toEqual(["employees"])
    expect(claims.preferred_username).toBeUndefined()
  })

  it("omits picture when the account has neither an upload nor an external URL", () => {
    const claims = buildUserClaims(ENV, user, [], ["openid", "profile"])
    expect(claims.picture).toBeUndefined()
  })

  it("returns the external picture when no avatar was uploaded", () => {
    const claims = buildUserClaims(
      ENV,
      { ...user, picture: "https://cdn.example.com/a.png" },
      [],
      ["openid", "profile"],
    )
    expect(claims.picture).toBe("https://cdn.example.com/a.png")
  })

  it("prefers an uploaded avatar and returns an absolute issuer URL", () => {
    const claims = buildUserClaims(
      ENV,
      { ...user, picture: "https://cdn.example.com/a.png", avatarKey: AVATAR_KEY },
      [],
      ["openid", "profile"],
    )
    expect(claims.picture).toBe(`https://auth.pangda.app/avatars/${AVATAR_KEY}`)
  })

  it("withholds picture without the profile scope", () => {
    const claims = buildUserClaims(ENV, { ...user, avatarKey: AVATAR_KEY }, [], ["openid", "email"])
    expect(claims.picture).toBeUndefined()
  })
})
