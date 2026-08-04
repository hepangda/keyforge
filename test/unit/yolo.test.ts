import { describe, expect, it } from "vitest"
import { isYoloEnabled, YOLO_ENVIRONMENT, yoloAllow } from "../../src/operations/yolo"

function yoloEnv(environment: string, yoloMode?: string) {
  return {
    ENVIRONMENT: environment,
    ...(yoloMode === undefined ? {} : { YOLO_MODE: yoloMode }),
  } as unknown as Env
}

describe("yolo mode switch", () => {
  it("is enabled only for dev with the exact string true", () => {
    expect(YOLO_ENVIRONMENT).toBe("dev")
    expect(isYoloEnabled(yoloEnv("dev", "true"))).toBe(true)
  })

  it("stays off in every environment other than dev", () => {
    for (const environment of ["local", "test", "production", "staging", "unexpected"]) {
      expect(isYoloEnabled(yoloEnv(environment, "true"))).toBe(false)
    }
  })

  it("fails closed for any value that is not exactly true", () => {
    for (const value of [undefined, "", "1", "TRUE", "True", " true", "true ", "yes", "false"]) {
      expect(isYoloEnabled(yoloEnv("dev", value))).toBe(false)
    }
  })

  it("yoloAllow mirrors the switch so callers can short-circuit a check", () => {
    expect(yoloAllow(yoloEnv("dev", "true"), "csrf")).toBe(true)
    expect(yoloAllow(yoloEnv("dev", "false"), "csrf")).toBe(false)
    expect(yoloAllow(yoloEnv("production", "true"), "csrf")).toBe(false)
  })
})
