export interface GetResponse {
  readonly status: number
  readonly body: unknown
}

export interface GetRequest {
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
}

export interface HttpTransport {
  get(request: GetRequest): Promise<GetResponse>
}

export class FetchHttpTransport implements HttpTransport {
  constructor(
    private readonly timeoutMs = 10_000,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async get(request: GetRequest): Promise<GetResponse> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs)

    try {
      const response = await this.fetchImpl(request.url, {
        method: 'GET',
        headers: request.headers,
        redirect: 'manual',
        signal: controller.signal,
      })

      const text = await response.text()
      let body: unknown = text

      if (text.length > 0) {
        try {
          body = JSON.parse(text) as unknown
        } catch {
          body = text
        }
      }

      return { status: response.status, body }
    } finally {
      clearTimeout(timeout)
    }
  }
}

export function bearerHeaders(secret: string): Readonly<Record<string, string>> {
  return Object.freeze({
    Authorization: `Bearer ${secret}`,
    Accept: 'application/json',
  })
}

export function assertNoRedirect(status: number): void {
  if (status >= 300 && status < 400) {
    throw new Error(`Provider returned redirect status ${status}; redirects are disabled`)
  }
}
