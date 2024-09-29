import type { Cache as CachifiedCache } from '@epic-web/cachified'
import { AsyncLocalStorage } from 'node:async_hooks'

export const cacheContext = new AsyncLocalStorage<CachifiedCache>()

const cacheObject = {
  get cache() {
    return cacheContext.getStore()
  },
}

cacheObject.cache
