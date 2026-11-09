import { randomUUID } from 'node:crypto'

const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/

export function requestId(candidate?: string): string {
  if (candidate && REQUEST_ID_PATTERN.test(candidate)) return candidate
  return randomUUID()
}
