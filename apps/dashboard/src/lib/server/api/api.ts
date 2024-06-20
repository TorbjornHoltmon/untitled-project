import { Hono } from 'hono'
import { userApi } from './user'
import { parseServerEnv } from '$lib/env/server-env'
import type { ServerEnv } from '$lib/env/server-env'

export type HonoApiContext = {
  Variables: {
    parsedEnv: ServerEnv
  }
  Bindings: {
    KV: KVNamespace
  }
}

export interface CreateApiOptions {
  env: ServerEnv
}

export function createApi(options: CreateApiOptions) {
  return new Hono<HonoApiContext>()
    .use((c, next) => {
      const env = parseServerEnv(options.env)
      c.set('parsedEnv', env)
      return next()
    })
    .basePath('/api/untitled-project')
    .route('/user', userApi)
}

export type ApiRoutes = ReturnType<typeof createApi>
