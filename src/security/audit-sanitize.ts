export const AUDIT_DETAIL_MAX_BYTES = 1_024
export const AUDIT_METADATA_MAX_BYTES = 4_096
export const AUDIT_METADATA_MAX_KEYS = 32
export const AUDIT_METADATA_KEY_MAX_BYTES = 64
export const AUDIT_METADATA_MAX_DEPTH = 4
export const AUDIT_METADATA_MAX_ARRAY_ITEMS = 32
export const AUDIT_METADATA_STRING_MAX_BYTES = 512
export const AUDIT_METADATA_MAX_NODES = 256

type JsonPrimitive = string | number | boolean | null
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue }

const encoder = new TextEncoder()
const FORBIDDEN_METADATA_KEYS = new Set(["__proto__", "prototype", "constructor"])

function utf8Length(value: string): number {
  return encoder.encode(value).byteLength
}

function truncateUtf8(value: string, maximumBytes: number): string {
  if (utf8Length(value) <= maximumBytes) return value
  let output = ""
  let bytes = 0
  for (const character of value) {
    const characterBytes = utf8Length(character)
    if (bytes + characterBytes > maximumBytes) break
    output += character
    bytes += characterBytes
  }
  return output
}

export function sanitizeAuditDetail<T extends string | null | undefined>(detail: T): T {
  if (typeof detail !== "string") return detail
  return truncateUtf8(detail, AUDIT_DETAIL_MAX_BYTES) as T
}

export function isBoundedAuditDetail(value: string): boolean {
  return utf8Length(value) <= AUDIT_DETAIL_MAX_BYTES
}

type SanitizeState = {
  readonly seen: WeakSet<object>
  nodesRemaining: number
  truncated: boolean
}

function safeEntries(value: object, state: SanitizeState): Array<[string, unknown]> {
  try {
    return Object.entries(value)
  } catch {
    state.truncated = true
    return []
  }
}

function sanitizeValue(value: unknown, depth: number, state: SanitizeState): JsonValue {
  if (value === null) return null
  switch (typeof value) {
    case "string": {
      const sanitized = truncateUtf8(value, AUDIT_METADATA_STRING_MAX_BYTES)
      if (sanitized !== value) state.truncated = true
      return sanitized
    }
    case "boolean":
      return value
    case "number":
      if (Number.isFinite(value)) return value
      state.truncated = true
      return null
    case "bigint":
      state.truncated = true
      return truncateUtf8(value.toString(), AUDIT_METADATA_STRING_MAX_BYTES)
    case "undefined":
    case "function":
    case "symbol":
      state.truncated = true
      return null
  }

  if (depth >= AUDIT_METADATA_MAX_DEPTH) {
    state.truncated = true
    return "[max_depth]"
  }
  if (state.nodesRemaining <= 0) {
    state.truncated = true
    return "[truncated]"
  }
  state.nodesRemaining -= 1
  if (state.seen.has(value)) {
    state.truncated = true
    return "[circular]"
  }
  state.seen.add(value)

  if (Array.isArray(value)) {
    if (value.length > AUDIT_METADATA_MAX_ARRAY_ITEMS) state.truncated = true
    const result = value
      .slice(0, AUDIT_METADATA_MAX_ARRAY_ITEMS)
      .map((item) => sanitizeValue(item, depth + 1, state))
    state.seen.delete(value)
    return result
  }

  const result = Object.create(null) as Record<string, JsonValue>
  const entries = safeEntries(value, state)
  if (entries.length > AUDIT_METADATA_MAX_KEYS) state.truncated = true
  for (const [rawKey, item] of entries.slice(0, AUDIT_METADATA_MAX_KEYS)) {
    const key = truncateUtf8(rawKey, AUDIT_METADATA_KEY_MAX_BYTES)
    if (
      key !== rawKey ||
      key === "" ||
      FORBIDDEN_METADATA_KEYS.has(key) ||
      Object.hasOwn(result, key)
    ) {
      state.truncated = true
      if (key === "" || FORBIDDEN_METADATA_KEYS.has(key) || Object.hasOwn(result, key)) continue
    }
    result[key] = sanitizeValue(item, depth + 1, state)
  }
  state.seen.delete(value)
  return result
}

function serializedLength(value: unknown): number {
  return utf8Length(JSON.stringify(value))
}

/** Convert application metadata to bounded, JSON-safe data for Queue and D1. */
export function sanitizeAuditMetadata(
  metadata: unknown,
): Record<string, unknown> | null | undefined {
  if (metadata === null || metadata === undefined) return metadata
  const state: SanitizeState = {
    seen: new WeakSet<object>(),
    nodesRemaining: AUDIT_METADATA_MAX_NODES,
    truncated: false,
  }
  const sanitized = sanitizeValue(metadata, 0, state)
  if (Array.isArray(sanitized) || sanitized === null || typeof sanitized !== "object") {
    return { _truncated: true }
  }

  const bounded = Object.create(null) as Record<string, JsonValue>
  for (const [key, value] of Object.entries(sanitized)) {
    const candidate = { ...bounded, [key]: value }
    if (serializedLength(candidate) <= AUDIT_METADATA_MAX_BYTES) {
      bounded[key] = value
    } else {
      state.truncated = true
    }
  }

  if (state.truncated) {
    while (
      Object.keys(bounded).length >= AUDIT_METADATA_MAX_KEYS ||
      serializedLength({ ...bounded, _truncated: true }) > AUDIT_METADATA_MAX_BYTES
    ) {
      const lastKey = Object.keys(bounded).at(-1)
      if (lastKey === undefined) break
      delete bounded[lastKey]
    }
    bounded["_truncated"] = true
  }
  return bounded
}

function isBoundedValue(
  value: unknown,
  depth: number,
  seen: WeakSet<object>,
  state: { nodes: number },
): boolean {
  if (value === null || typeof value === "boolean") return true
  if (typeof value === "string") return utf8Length(value) <= AUDIT_METADATA_STRING_MAX_BYTES
  if (typeof value === "number") return Number.isFinite(value)
  if (typeof value !== "object" || depth >= AUDIT_METADATA_MAX_DEPTH) return false
  state.nodes += 1
  if (state.nodes > AUDIT_METADATA_MAX_NODES || seen.has(value)) return false
  seen.add(value)

  if (Array.isArray(value)) {
    if (value.length > AUDIT_METADATA_MAX_ARRAY_ITEMS) return false
    const valid = value.every((item) => isBoundedValue(item, depth + 1, seen, state))
    seen.delete(value)
    return valid
  }

  let entries: Array<[string, unknown]>
  try {
    entries = Object.entries(value)
  } catch {
    return false
  }
  if (entries.length > AUDIT_METADATA_MAX_KEYS) return false
  const valid = entries.every(
    ([key, item]) =>
      key !== "" &&
      !FORBIDDEN_METADATA_KEYS.has(key) &&
      utf8Length(key) <= AUDIT_METADATA_KEY_MAX_BYTES &&
      isBoundedValue(item, depth + 1, seen, state),
  )
  seen.delete(value)
  return valid
}

export function isBoundedAuditMetadata(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false
  try {
    return (
      serializedLength(value) <= AUDIT_METADATA_MAX_BYTES &&
      isBoundedValue(value, 0, new WeakSet<object>(), { nodes: 0 })
    )
  } catch {
    return false
  }
}
