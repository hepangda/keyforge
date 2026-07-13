import type { Context } from "hono"
import { describe, expect, it } from "vitest"
import { authenticateClient } from "../../src/oauth/clients"
import type { AppBindings } from "../../src/types/app"

function contextWithBasic(credentials: string, onDatabaseAccess: () => void): Context<AppBindings> {
  return {
    req: {
      header: (name: string) =>
        name.toLowerCase() === "authorization" ? `Basic ${btoa(credentials)}` : undefined,
    },
    env: {
      DB: {
        prepare: () => {
          onDatabaseAccess()
          throw new Error("database must not be queried")
        },
      },
    },
  } as unknown as Context<AppBindings>
}

describe("OAuth client authentication input limits", () => {
  it("rejects an overlong Basic client_id before a D1 lookup", async () => {
    let databaseAccessed = false
    const context = contextWithBasic(`${"c".repeat(129)}:secret`, () => {
      databaseAccessed = true
    })

    await expect(authenticateClient(context, new URLSearchParams())).rejects.toMatchObject({
      code: "invalid_client",
      status: 401,
    })
    expect(databaseAccessed).toBe(false)
  })

  it("rejects an overlong Basic client_secret before a D1 lookup", async () => {
    let databaseAccessed = false
    const context = contextWithBasic(`client:${"s".repeat(513)}`, () => {
      databaseAccessed = true
    })

    await expect(authenticateClient(context, new URLSearchParams())).rejects.toMatchObject({
      code: "invalid_client",
      status: 401,
    })
    expect(databaseAccessed).toBe(false)
  })

  it("rejects a syntactically invalid Basic client_id before a D1 lookup", async () => {
    let databaseAccessed = false
    const context = contextWithBasic("client id\nwith-control:secret", () => {
      databaseAccessed = true
    })

    await expect(authenticateClient(context, new URLSearchParams())).rejects.toMatchObject({
      code: "invalid_client",
      status: 401,
    })
    expect(databaseAccessed).toBe(false)
  })
})
