import { getLoggerContext } from '../context/logger-context'

export interface WaitUntil {
  (promise: Promise<any>): void
}

export async function waitUntilMock(promise: Promise<any>): Promise<void> {
  try {
    await promise
  } catch (error) {
    const logger = getLoggerContext()
    logger.error('m', {})
    // noop
  }
}
