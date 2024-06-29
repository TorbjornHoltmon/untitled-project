import { relations } from 'drizzle-orm'
import { index, int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { variant } from '../product/variant'
import { sqliteISODateNow } from '../sqlite-now'
import { ulid } from '../ulid'
import { order } from './order'

export const orderItem = sqliteTable(
  'order_item',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => `order_item_${ulid()}`),
    skuId: text('sku_id')
      .references(() => variant.skuId)
      .notNull(),
    orderId: text('order_id')
      .references(() => order.id, {
        onDelete: 'cascade',
      })
      .notNull(),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
    price: int('price'),
    // calculated prices
    basePrice: int('base_price'),
    taxAmount: int('tax_amount'),
    discountAmount: int('discount_amount'),
    totalAmount: int('total_amount'),
  },
  (currentTable) => ({
    orderIdIndex: index('order_item_table_order_id_idx').on(currentTable.orderId),
    skuIdIndex: index('order_item_table_sku_id_idx').on(currentTable.skuId),
  }),
)

export const orderItemRelations = relations(orderItem, ({ many, one }) => ({
  order: one(order),
}))

export type OrderItemSqlite = typeof orderItem.$inferInsert
