import { relations } from 'drizzle-orm'
import { sqliteTable, text, type AnySQLiteColumn, index } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'
import { productCategory } from './product-category'

export const category = sqliteTable(
  'category',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => ulid()),
    title: text('title', { length: 256, mode: 'text' }),
    slug: text('slug', { length: 256, mode: 'text' }),
    description: text('description', { mode: 'text' }),
    parentId: text('parent_id').references((): AnySQLiteColumn => category.id),
    createdAt: text('created_at', { mode: 'text' }).default(sqliteISODateNow),
    updatedAt: text('updated_at', { mode: 'text' }).default(sqliteISODateNow),
  },
  (currentTable) => ({}),
)

export const categoryRelations = relations(category, ({ many, one }) => ({
  productCategory: many(productCategory),
  parentCategory: one(category, {
    fields: [category.parentId],
    references: [category.id],
  }),
}))

export type Category = typeof category.$inferSelect
