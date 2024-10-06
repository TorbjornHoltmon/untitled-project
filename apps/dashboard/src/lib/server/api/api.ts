import type { ServerEnv } from '$lib/env/server-env'
import { parseServerEnv } from '$lib/env/server-env'
import { Hono } from 'hono'
import { productsApi } from './products-api'

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
    .route('/products', productsApi)
}

export type ApiRoutes = ReturnType<typeof createApi>
