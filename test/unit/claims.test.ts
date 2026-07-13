import { describe, expect, it } from "vitest"
import { buildUserClaims } from "../../src/oidc/claims"
import { asUserId, type User } from "../../src/types/domain"

const user: User = {
  id: asUserId("usr_claims"),
  email: "claims@pangda.app",
  emailVerified: true,
  name: "Claims User",
  picture: null,
  userType: "internal",
  disabled: false,
  createdAt: 1,
}

describe("OIDC claim scope policy", () => {
  it("withholds groups and user_type without the groups scope", () => {
    const claims = buildUserClaims(user, ["employees"], ["openid", "profile"])
    expect(claims.groups).toBeUndefined()
    expect(claims.user_type).toBeUndefined()
  })

  it("releases groups and user_type only with the groups scope", () => {
    const claims = buildUserClaims(user, ["employees"], ["openid", "groups"])
    expect(claims.groups).toEqual(["employees"])
    expect(claims.user_type).toBe("internal")
  })
})
