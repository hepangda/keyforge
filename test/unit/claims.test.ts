import { describe, expect, it } from "vitest"
import { buildUserClaims } from "../../src/oidc/claims"
import { asUserId, type User } from "../../src/types/domain"

const user: User = {
  id: asUserId("usr_claims"),
  email: "claims@pangda.app",
  alias: "claimsuser",
  emailVerified: true,
  name: "Claims User",
  picture: null,
  disabled: false,
  createdAt: 1,
}

describe("OIDC claim scope policy", () => {
  it("releases the username with profile while withholding groups", () => {
    const claims = buildUserClaims(user, ["employees"], ["openid", "profile"])
    expect(claims.groups).toBeUndefined()
    expect(claims.preferred_username).toBe("claimsuser")
  })

  it("releases groups only with the groups scope", () => {
    const claims = buildUserClaims(user, ["employees"], ["openid", "groups"])
    expect(claims.groups).toEqual(["employees"])
    expect(claims.preferred_username).toBeUndefined()
  })
})
