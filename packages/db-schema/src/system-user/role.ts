import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'

export const role = sqliteTable(
  'role',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    name: text('name').notNull(),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({
    createdAtIndex: index('role_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('role_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)
