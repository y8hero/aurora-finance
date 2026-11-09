export type JsonShape =
  | 'null'
  | 'string'
  | 'number'
  | 'boolean'
  | 'object'
  | 'array'
  | 'unknown'

export interface ShapeNode {
  readonly type: JsonShape
  readonly fields?: Readonly<Record<string, ShapeNode>>
  readonly items?: ShapeNode
}

export function responseShape(value: unknown): ShapeNode {
  if (value === null) return { type: 'null' }

  if (Array.isArray(value)) {
    const first = value[0]
    return {
      type: 'array',
      items: first === undefined ? { type: 'unknown' } : responseShape(first),
    }
  }

  switch (typeof value) {
    case 'string':
      return { type: 'string' }
    case 'number':
      return { type: 'number' }
    case 'boolean':
      return { type: 'boolean' }
    case 'object': {
      const fields: Record<string, ShapeNode> = {}
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        fields[key] = responseShape(child)
      }
      return { type: 'object', fields }
    }
    default:
      return { type: 'unknown' }
  }
}

export function redactedResponseShape(value: unknown): ShapeNode {
  return responseShape(value)
}
