import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { sqliteISODateNow } from '../utils/sqlite-now'
import { sqliteUUIDv7 } from '../utils/sqlite-uuid7'

export const auditLog = sqliteTable(
  'audit_log',
  {
    id: text('id').primaryKey().notNull().default(sqliteUUIDv7('role')),
    reference: text('reference').notNull(),
    item: text('item', {
      mode: 'json',
    }).notNull(),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({
    createdAtIndex: index('audit_log_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('audit_log_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)
