import { relations } from 'drizzle-orm'
import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'
import { product } from './product'

export const productGroup = sqliteTable(
  'product_group',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => `product_group_${ulid()}`),
    title: text('title'),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({
    createdAtIndex: index('product_group_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('product_group_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const productGroupRelations = relations(productGroup, ({ many, one }) => ({
  products: many(product),
}))

export type ProductGroupSqlite = typeof productGroup.$inferSelect
