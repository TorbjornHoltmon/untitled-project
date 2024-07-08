import { relations } from 'drizzle-orm'
import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { sqliteISODateNow } from '../utils/sqlite-now'
import { variant } from './variant'
import { productGroup } from './product-group'
import { sqliteUUIDv7 } from '../utils/sqlite-uuid7'

export const product = sqliteTable(
  'product',
  {
    id: text('id').primaryKey().notNull().default(sqliteUUIDv7('role')),
    title: text('title'),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
    // Foreign keys
    productGroupId: text('product_group_id').references(() => productGroup.id, {
      onDelete: 'cascade',
    }),
  },
  (currentTable) => ({
    productGroupIdIndex: index('product_table_product_group_id_idx').on(currentTable.productGroupId),
    createdAtIndex: index('product_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('product_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const productRelations = relations(product, ({ many, one }) => ({
  variants: many(variant),
  productGroup: one(product),
}))

export type Product = typeof product.$inferSelect
