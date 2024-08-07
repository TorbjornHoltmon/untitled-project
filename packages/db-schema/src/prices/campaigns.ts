import { int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { sqliteISODateNow } from '../utils/sqlite-now'
import { ulid } from '../ulid'

export const campaign = sqliteTable(
  'campaign',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => 'campaign_' + ulid()),
    name: text('name').notNull(),
    startDate: text('start_date').default(sqliteISODateNow).notNull(),
    endDate: text('end_date').default(sqliteISODateNow).notNull(),
    priority: int('priority').notNull(),
    combinable: int('combinable', { mode: 'boolean' }).notNull(),
  },
  (currentTable) => ({}),
)

export type Campaign = typeof campaign.$inferInsert
