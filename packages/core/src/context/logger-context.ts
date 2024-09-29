import { AsyncLocalStorage } from 'node:async_hooks'
import type { Logger } from '../common/logger-interface'
import { DefaultLogger } from '../common/default-logger'

export const loggerContext = new AsyncLocalStorage<Logger>()

export function getLoggerContext(): Logger {
  const logger = loggerContext.getStore()
  if (!logger) {
    return new DefaultLogger()
  }
  return logger
}
