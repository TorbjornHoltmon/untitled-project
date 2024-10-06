import type { Cache as CachifiedCache } from '@epic-web/cachified'
import type { Database } from '@untitled-project/db/types'
import { AsyncLocalStorage } from 'node:async_hooks'
import { DefaultLogger } from '../common/default-logger'
import { invariant } from '../common/invariant'
import type { Logger } from '../common/logger-interface'
import type { WaitUntil } from '../common/wait-until'
import { waitUntilMock } from '../common/wait-until'

interface AppContext {
  logger: Logger
  cache: CachifiedCache
  db: Database
  request: Request
  waitUntil: WaitUntil
}

export const contextAsyncLocalStorage = new AsyncLocalStorage<AppContext>()

export const context: AppContext = {
  get cache() {
    const cache = contextAsyncLocalStorage.getStore()?.cache
    invariant(cache, 'Cache not found in app context')
    return cache
  },
  get logger() {
    const logger = contextAsyncLocalStorage.getStore()?.logger
    return logger ?? new DefaultLogger()
  },
  get waitUntil() {
    const waitUntil = contextAsyncLocalStorage.getStore()?.waitUntil
    return waitUntil ?? waitUntilMock
  },
  get db() {
    const db = contextAsyncLocalStorage.getStore()?.db
    invariant(db, 'Database not found in app context')
    return db
  },
  get request() {
    const request = contextAsyncLocalStorage.getStore()?.request
    invariant(request, 'Request not found in app context')
    return request
  },
}
