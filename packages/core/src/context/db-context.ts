import type { Database } from '@untitled-project/db/types'
import { AsyncLocalStorage } from 'node:async_hooks'

export const dbContext = new AsyncLocalStorage<Database>()
