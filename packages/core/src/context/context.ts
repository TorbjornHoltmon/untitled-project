import { cacheContext } from './cache-context'
import { dbContext } from './db-context'

export const context = {
  get cache() {
    return cacheContext.getStore()
  },
  get db() {
    return dbContext.getStore()
  },
}
