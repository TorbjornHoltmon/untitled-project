import { relations } from 'drizzle-orm'
import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { taxRate } from '../prices/tax-rate'
import { sqliteISODateNow } from '../sqlite-now'
import { variant } from './variant'

export const product = sqliteTable(
  'product',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    title: text('title'),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({
    idIndex: index('product_table_id_idx').on(currentTable.id),
    createdAtIndex: index('product_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('product_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const productRelations = relations(product, ({ many, one }) => ({
  variants: many(variant),
  taxRate: one(taxRate, {
    fields: [product.id],
    references: [taxRate.productId],
  }),
}))

export type Product = typeof product.$inferSelect
