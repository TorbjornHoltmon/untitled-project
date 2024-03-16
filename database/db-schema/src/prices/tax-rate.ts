import { relations } from 'drizzle-orm'
import { index, int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { product } from '../product/product'
import { sqliteISODateNow } from '../sqlite-now'
import { ulid } from '../ulid'

export const taxRate = sqliteTable(
  'taxRate',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    name: text('name').notNull(),
    rate: int('rate').notNull(), // tax rate as a percentage
    productId: text('product_id')
      .notNull()
      .references(() => product.id),
    createdAt: text('created_at').default(sqliteISODateNow),
    updatedAt: text('updated_at').default(sqliteISODateNow),
  },
  (currentTable) => ({
    createdAtIndex: index('taxRate_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('taxRate_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const taxRateRelations = relations(taxRate, ({ many }) => ({
  products: many(product),
}))
