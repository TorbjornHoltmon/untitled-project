import { relations } from 'drizzle-orm'
import { sqliteTable, text, type AnySQLiteColumn } from 'drizzle-orm/sqlite-core'
import { sqliteISODateNow } from '../utils/sqlite-now'
import { productCategory } from './product-category'
import { UUIDv7 } from '../utils/uuidv7'

export const category = sqliteTable(
  'category',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      // TODO: Replace with UUIDv7 on sqlite side, when support is added.
      .$defaultFn(() => UUIDv7('category')),
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

export type CategorySqlite = typeof category.$inferSelect
