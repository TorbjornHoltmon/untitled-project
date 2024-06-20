import { Database } from 'bun:sqlite'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { migrate } from 'drizzle-orm/bun-sqlite/migrator'

const sqlite = new Database(`${import.meta.dir}/sqlite.db`)
const db = drizzle(sqlite)
await migrate(db, { migrationsFolder: `${import.meta.dir}/drizzle-migrations` })
console.log('Migration completed')
