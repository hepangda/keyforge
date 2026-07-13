/** Compile-time exhaustiveness guard for discriminated unions. */
export function assertNever(value: never): never {
  throw new Error(`Unexpected variant: ${String(value)}`)
}
