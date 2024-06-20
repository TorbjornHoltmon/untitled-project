import { relations } from 'drizzle-orm'
import { index, int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'
import { cartItem } from './cart-item'

export const cart = sqliteTable(
  'cart',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    active: int('active', { mode: 'boolean' }).$default(() => true),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({
    createdAtIndex: index('cart_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('cart_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const cartRelations = relations(cart, ({ many }) => ({
  items: many(cartItem),
}))

export type Cart = typeof cart.$inferInsert
