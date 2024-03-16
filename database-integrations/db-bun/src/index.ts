/// <reference types="@types/bun" />

import * as schema from '@untitled-project/db-schema'
import { Database } from 'bun:sqlite'
import { drizzle } from 'drizzle-orm/bun-sqlite'

const sqlite = new Database(`${import.meta.dir}/sqlite.db`)

const db = drizzle(sqlite, {
  schema,
})

const sql = await db.query.cart.findMany({
  columns: {
    id: true,
    active: true,
    createdAt: true,
    updatedAt: true,
  },
  with: {
    items: {
      with: {
        variant: {
          with: {
            product: true,
          },
        },
      },
    },
  },
})

console.log(sql)
