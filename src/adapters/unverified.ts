/**
 * Thrown by every provider method that depends on facts not yet confirmed in Phase 0.
 * Message always starts with "UNVERIFIED: complete Phase 0" so it is greppable in logs.
 */
export class UnverifiedError extends Error {
  override name = 'UnverifiedError'
  constructor(what: string) {
    super(`UNVERIFIED: complete Phase 0 — ${what}`)
  }
}

export function unverified(what: string): never {
  throw new UnverifiedError(what)
}
