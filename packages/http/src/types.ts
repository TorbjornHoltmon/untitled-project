import { SearchParamsOptions } from './url/search-params'

export interface RetailorHttpResponse extends Response {
  json: <T = unknown>() => Promise<T>
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'HEAD' | 'DELETE'

export type Input = string | URL | Request

export type RequestHeaders = HeadersInit | Record<string, string | undefined>

export interface RequestOptions extends Omit<RequestInit, 'headers'> {
  headers?: RequestHeaders
  /**
  Shortcut for sending JSON. Use this instead of the `body` option.

  Accepts any plain object or value, which will be `JSON.stringify()`'d and sent in the body with the correct header set.
  */
  json?: unknown

  /**
	Search parameters to include in the request URL. Setting this will override all existing search parameters in the input URL.

	Accepts any value supported by [`URLSearchParams()`](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams/URLSearchParams).
	*/
  searchParams?: SearchParamsOptions

  throwHttpErrors?: boolean
}
