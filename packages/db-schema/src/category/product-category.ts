import { relations } from 'drizzle-orm'
import { sqliteTable, text, index } from 'drizzle-orm/sqlite-core'
import { product } from '../product/product'
import { category } from './category'

export const productCategory = sqliteTable(
  'product_category',
  {
    productId: text('product_id').references(() => product.id),
    categoryId: text('category_id').references(() => category.id),
  },
  (currentTable) => ({
    productIdIndex: index('product_category_table_product_id_idx').on(currentTable.productId),
    categoryIdIndex: index('product_category_table_category_id_idx').on(currentTable.categoryId),
  }),
)

export const productCategoryRelations = relations(productCategory, ({ one }) => ({
  product: one(product),
  category: one(category),
}))

export type ProductCategory = typeof category.$inferSelect
