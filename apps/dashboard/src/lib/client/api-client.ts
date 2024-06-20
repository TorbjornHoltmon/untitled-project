import { hc } from 'hono/client'
import type { ApiRoutes } from '$lib/server/api/api'

let browserClient: ReturnType<typeof hc<ApiRoutes>>

export const createApiClient = (_fetch?: Window['fetch']) => {
  const isBrowser = typeof window !== 'undefined'
  const origin = isBrowser ? window.location.origin : ''

  if (isBrowser && browserClient) {
    return browserClient
  }

  const client = hc<ApiRoutes>(origin + '/api/untitled-project', { fetch: _fetch })

  if (isBrowser) {
    browserClient = client
  }

  return client
}
