/** Canonicalize a user_code for hashing/lookup: uppercase, strip separators. */
export function normalizeUserCode(input: string): string {
  return input.toUpperCase().replace(/[^A-Z0-9]/g, "")
}
