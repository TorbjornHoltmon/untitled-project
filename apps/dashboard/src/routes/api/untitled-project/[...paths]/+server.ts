import type { RequestEvent, RequestHandler } from '@sveltejs/kit'
// import { env } from '$env/dynamic/private'

import { createApi } from '$lib/server/api/api'

export const fallback: RequestHandler = ({ request, platform, locals }: RequestEvent) => {
  // How to access env
  // console.log(env)
  const api = createApi({
    env: {
      AUTH_SECRET: 'secret',
    },
  })
  // KV Has to be mocked?
  return api.fetch(request, {
    KV: platform?.env?.KV,
  })
}
