import { relations } from 'drizzle-orm'
import { index, int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../utils/sqlite-now'
import { product } from './product'

export const variant = sqliteTable(
  'variant',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    skuId: text('sku_id').unique().notNull(),
    ean: text('ean').unique().notNull(),
    title: text('title'),
    price: int('price'),
    createdAt: text('created_at').default(sqliteISODateNow),
    updatedAt: text('updated_at').default(sqliteISODateNow),

    // Foreign keys
    productId: text('product_id').references(() => product.id, {
      onDelete: 'cascade',
    }),
  },
  (currentTable) => ({
    productIdIndex: index('variant_table_product_id_idx').on(currentTable.productId),
    createdAtIndex: index('variant_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('variant_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const variantRelations = relations(variant, ({ one, many }) => ({
  product: one(product, {
    fields: [variant.productId],
    references: [product.id],
  }),
}))

export type Variant = typeof variant.$inferInsert
