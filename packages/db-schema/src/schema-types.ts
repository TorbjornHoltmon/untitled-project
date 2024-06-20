import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import type * as schema from './index'

export type Schema = typeof schema
export type DrizzleSQLiteDB = BaseSQLiteDatabase<'sync', void, typeof schema>
