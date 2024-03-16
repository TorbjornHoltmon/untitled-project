/// <reference types="@types/bun" />

import * as schema from '@untitled-project/db-schema'
import { MockTimeKeeper, SeedProducts } from '@untitled-project/db-seed'
import { Database } from 'bun:sqlite'
import { drizzle } from 'drizzle-orm/bun-sqlite'

const sqlite = new Database(`${import.meta.dir}/sqlite.db`)

const db = drizzle(sqlite, {
  schema,
})

async function seed() {
  const products = new SeedProducts({
    db,
    timeKeeper: new MockTimeKeeper({}),
    size: 10_000,
  })
  await products.seedProducts()
}

await seed()
console.log('Seeding complete')
