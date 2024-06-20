import { sqliteTable, int, index, text } from 'drizzle-orm/sqlite-core'
import { relations } from 'drizzle-orm'
import { variant } from '../product/variant'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'
import { cart } from './cart'

export const cartItem = sqliteTable(
  'cart_item',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    skuId: text('sku_id')
      .references(() => variant.skuId)
      .notNull(),
    cartId: int('cart_id')
      .references(() => cart.id, { onDelete: 'cascade' })
      .notNull(),
    price: int('price_id').notNull(),
    createdAt: text('created_at').default(sqliteISODateNow).notNull(),
    updatedAt: text('updated_at').default(sqliteISODateNow).notNull(),
  },
  (currentTable) => ({
    cartIdIndex: index('cart_item_table_cart_id_idx').on(currentTable.cartId),
    skuIdIndex: index('cart_item_table_sku_id_idx').on(currentTable.skuId),
    createdAtIndex: index('cart_item_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('cart_item_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const cartItemRelations = relations(cartItem, ({ one, many }) => ({
  cart: one(cart, {
    fields: [cartItem.cartId],
    references: [cart.id],
  }),
  variant: one(variant, {
    fields: [cartItem.skuId],
    references: [variant.skuId],
  }),
}))

export type CartItem = typeof cartItem.$inferInsert
