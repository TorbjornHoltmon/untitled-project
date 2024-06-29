import { sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { relations } from 'drizzle-orm'
import { cart } from '../cart/cart'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'
import { orderItem } from './order-item'

export const order = sqliteTable(
  'order',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => `order_${ulid()}`),
    cartId: text('cart_id')
      .references(() => cart.id)
      .notNull(),
    orderSnapshot: text('order_snapshot').$type<{ version: string }>(),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({}),
)

export const orderRelations = relations(order, ({ many, one }) => ({
  items: many(orderItem),
  cart: one(cart),
}))

export type OrderSqlite = typeof order.$inferInsert
