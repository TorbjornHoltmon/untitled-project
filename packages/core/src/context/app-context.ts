import { AsyncLocalStorage } from 'node:async_hooks'
import type { Logger } from '../common/logger-interface'
import type { WaitUntil } from '../common/wait-until'

interface AppContext {
  logger: Logger
  waitUntil: WaitUntil
}

export const appContext = new AsyncLocalStorage<AppContext>()
