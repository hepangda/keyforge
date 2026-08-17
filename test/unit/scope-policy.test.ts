import { describe, expect, it } from "vitest"
import {
  isPermissionGroupControlledScope,
  RESOURCE_AUTHORIZED_SCOPES,
} from "../../src/oauth/scope-policy"

describe("permission-group scope policy", () => {
  it("leaves identity and session scopes to application/resource authorization", () => {
    expect(RESOURCE_AUTHORIZED_SCOPES).toEqual(["openid", "profile", "email", "offline_access"])
    for (const scope of RESOURCE_AUTHORIZED_SCOPES) {
      expect(isPermissionGroupControlledScope(scope)).toBe(false)
    }
  })

  it("keeps resource-specific capabilities under permission-group control", () => {
    expect(isPermissionGroupControlledScope("api.read")).toBe(true)
    expect(isPermissionGroupControlledScope("mcp.tools.execute")).toBe(true)
  })
})
