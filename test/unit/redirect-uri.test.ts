import { describe, expect, it } from "vitest"
import {
  isMcpResourceUriAllowed,
  isSafeMcpResourceUri,
  isSafeResourceUri,
} from "../../src/security/redirect-uri"

describe("isSafeResourceUri", () => {
  it.each([
    "https://mcp.example.com/mcp",
    "http://localhost:8788/mcp",
    "http://127.0.0.1:8788/mcp",
    "http://[::1]:8788/mcp",
    "urn:example:mcp",
  ])("accepts a deployable resource identifier %s", (resource) => {
    expect(isSafeResourceUri(resource)).toBe(true)
  })

  it.each([
    "http://mcp.example.com/mcp",
    "http://192.168.1.10/mcp",
    "https://user@mcp.example.com/mcp",
    "https://mcp.example.com/mcp#fragment",
    "not-a-uri",
  ])("rejects unsafe resource identifier %s", (resource) => {
    expect(isSafeResourceUri(resource)).toBe(false)
  })
})

describe("isSafeMcpResourceUri", () => {
  it.each([
    "https://mcp.example.com/mcp",
    "http://localhost:8788/mcp",
    "http://127.0.0.1:8788/mcp",
  ])("accepts an MCP HTTP transport identity %s", (resource) => {
    expect(isSafeMcpResourceUri(resource)).toBe(true)
  })

  it.each([
    "urn:example:mcp",
    "https://mcp.example.com/mcp?tenant=1",
    "http://mcp.example.com/mcp",
  ])("rejects ambiguous or non-transport MCP identity %s", (resource) => {
    expect(isSafeMcpResourceUri(resource)).toBe(false)
  })
})

describe("isMcpResourceUriAllowed", () => {
  it("accepts loopback only in local and always accepts HTTPS", () => {
    expect(isMcpResourceUriAllowed("local", "http://localhost:5173/mcp")).toBe(true)
    expect(isMcpResourceUriAllowed("production", "http://localhost:5173/mcp")).toBe(false)
    expect(isMcpResourceUriAllowed("production", "https://aaeasy.pangda.app/mcp")).toBe(true)
  })
})
