import { HttpTimeout, HttpTimeoutError } from './timeout'
import type { HttpMethod, RequestHeaders, RequestOptions, RetailorHttpResponse } from './types'
import { createSearchParams } from './url/search-params'

export type NewHttpClientOptions = {
  prefixUrl?: string
  debug: boolean
  retryPolicy?: RetryPolicy
}

type RetryPolicy = {
  retires: number
  retryTimeout: number
}

export type Input = string

export class NewHttpClient {
  prefixUrl?: string
  debug: boolean
  retryPolicy: RetryPolicy
  headers?: RequestHeaders

  constructor(options: NewHttpClientOptions) {
    this.debug = options.debug
    this.prefixUrl = options.prefixUrl
    // TODO: Actually merge...
    this.retryPolicy = options.retryPolicy ?? { retires: 1, retryTimeout: 10_000 }
  }

  public fetch = {
    post: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('POST', input, options)
    },
    get: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('GET', input, options)
    },
    put: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('PUT', input, options)
    },
    patch: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('PATCH', input, options)
    },
    head: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('HEAD', input, options)
    },
    delete: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('DELETE', input, options)
    },
  }

  // TODO
  public request = {
    post: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('POST', input, options)
    },
    get: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('GET', input, options)
    },
    put: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('PUT', input, options)
    },
    patch: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('PATCH', input, options)
    },
    head: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('HEAD', input, options)
    },
    delete: (input: Input, options?: RequestOptions): Promise<RetailorHttpResponse> => {
      return this.fetchAction('DELETE', input, options)
    },
  }

  protected fetchPromise(request: Request) {
    if (this.fetch) {
      return fetch(request)
    }
    return fetch(request)
  }

  protected mergeHeaders = (source1: RequestHeaders = {}, source2: RequestHeaders = {}, json: boolean): Headers => {
    const result = new Headers(source1 as HeadersInit)
    const isHeadersInstance = source2 instanceof Headers
    const source = new Headers(source2 as HeadersInit)

    for (const [key, value] of source.entries()) {
      if ((isHeadersInstance && value === 'undefined') || value === undefined) {
        result.delete(key)
      } else {
        result.set(key, value)
      }
    }

    if (json) {
      result.set('Content-Type', 'application/json')
    }

    return result
  }

  protected setBody = (options?: RequestOptions) => {
    if (options?.json !== undefined) {
      return JSON.stringify(options.json)
    }
    return options?.body
  }

  protected createRequest(method: HttpMethod, input: Input, options?: RequestOptions): Request {
    return new Request('')
  }

  protected async fetchAction(method: HttpMethod, input: Input, options?: RequestOptions): Promise<Response> {
    if (input.includes('?')) {
      // TODO: Remove search params from url
      throw new Error('cannot have search params, use searchParams')
    }

    const searchParams = createSearchParams(options?.searchParams)

    const mergedOptions: RequestInit = {
      headers: this.mergeHeaders(options?.headers, this.headers, options?.json !== undefined || !!options?.json),
      method,
      body: this.setBody(options),
      signal: options?.signal,
    }

    const request = this.fetchPromise(new Request(input, mergedOptions))

    const timeout = new HttpTimeout({ timeout: this.retryPolicy.retryTimeout })

    const responseOrTimeout = await Promise.race([request, timeout.start])
    timeout.clear()

    if (responseOrTimeout instanceof HttpTimeoutError) {
      throw responseOrTimeout
    }

    return responseOrTimeout
  }
}
