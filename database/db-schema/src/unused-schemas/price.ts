import { relations } from 'drizzle-orm'
import { index, int, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { variant } from '../product/variant'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'

export const price = sqliteTable(
  'price',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    price: int('price'),
    variantId: text('variant_id', { length: 256 })
      .notNull()
      .references(() => variant.id, { onDelete: 'set null' }),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({}),
)

export const priceRelations = relations(price, ({ one, many }) => ({
  variant: one(variant, {
    fields: [price.variantId],
    references: [variant.id],
  }),
}))
