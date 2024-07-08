import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { sqliteISODateNow } from '../utils/sqlite-now'
import { sqliteUUIDv7 } from '../utils/sqlite-uuid7'

export const role = sqliteTable(
  'role',
  {
    id: text('id').primaryKey().notNull().default(sqliteUUIDv7('role')),
    name: text('name').notNull(),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({
    createdAtIndex: index('role_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('role_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)
