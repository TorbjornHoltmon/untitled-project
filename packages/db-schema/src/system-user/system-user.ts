import { relations } from 'drizzle-orm'
import { index, sqliteTable, text } from 'drizzle-orm/sqlite-core'
import { ulid } from '../ulid'
import { sqliteISODateNow } from '../sqlite-now'
import { role } from './role'

export const systemUser = sqliteTable(
  'system_user',
  {
    id: text('id')
      .primaryKey()
      .notNull()
      .$defaultFn(() => `system_user_${ulid()}`),
    name: text('name').notNull(),
    email: text('email').notNull(),
    roleId: text('role_id').notNull(), // foreign key to role table
    createdAt: text('created_at').default(sqliteISODateNow),
    updatedAt: text('updated_at').default(sqliteISODateNow),
  },
  (currentTable) => ({
    emailIndex: index('system_user_table_email_idx').on(currentTable.email),
    roleIdIndex: index('system_user_table_roleId_idx').on(currentTable.roleId),
    createdAtIndex: index('system_user_table_created_at_idx').on(currentTable.createdAt),
    updatedAtIndex: index('system_user_table_updated_at_idx').on(currentTable.updatedAt),
  }),
)

export const systemUserRelations = relations(systemUser, ({ one }) => ({
  role: one(role),
}))

export const roleRelations = relations(role, ({ many }) => ({
  systemUsers: many(systemUser),
}))
