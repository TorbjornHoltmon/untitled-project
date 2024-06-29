import { sqliteTable, int, text, index } from 'drizzle-orm/sqlite-core'
import { relations } from 'drizzle-orm'
import { variant } from '../product/variant'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'

export const price = sqliteTable(
  'price',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => 'price_' + ulid()),
    skuId: text('sku_id')
      .references(() => variant.skuId)
      .notNull(),
    variantId: text('variant_id')
      .references(() => variant.id)
      .notNull(),
    amount: int('amount').notNull(),
    validFrom: text('valid_from').default(sqliteISODateNow).notNull(),
    validTo: text('valid_to'),
    currency: text('currency').notNull(),
  },
  (currentTable) => ({
    skuIdIndex: index('price_table_sku_id_idx').on(currentTable.skuId),
    variantIdIndex: index('price_table_variant_id_idx').on(currentTable.variantId),
  }),
)

export const priceRelations = relations(price, ({ one }) => ({
  variant: one(variant, {
    fields: [price.variantId],
    references: [variant.id],
  }),
  sku: one(variant, {
    fields: [price.skuId],
    references: [variant.skuId],
  }),
}))

export type Price = typeof price.$inferInsert
