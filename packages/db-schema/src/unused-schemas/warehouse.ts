/**
 * Not explored or used due to complexity. Will look into it later.
 */
import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'

export const warehouse = sqliteTable(
  'warehouse',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    name: text('name', { length: 256 }),
    createdAt: text('created_at', { mode: 'text' }).default(sqlLiteNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqlLiteNow),
  },
  (currentTable) => ({
    idIndex: index('warehouse_table_id_idx').on(currentTable.id),
  }),
)
