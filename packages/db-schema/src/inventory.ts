import { relations } from 'drizzle-orm'
import { index, int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { variant } from './product/variant'
import { ulid } from './ulid'

export const inventory = sqliteTable(
  'inventory',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    skuId: text('sku_id')
      .references(() => variant.skuId)
      .notNull(),
    quantity: int('quantity'),
    reservedQuantity: int('reserved_quantity'),
  },
  (currentTable) => ({
    idIndex: index('inventory_table_id_idx').on(currentTable.id),
    skuIdIndex: index('inventory_table_sku_id_idx').on(currentTable.skuId),
  }),
)

export const inventoryRelations = relations(inventory, ({ one }) => ({
  variant: one(variant, {
    fields: [inventory.skuId],
    references: [variant.skuId],
  }),
}))
