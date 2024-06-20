import type { DrizzleSQLiteDB } from '@untitled-project/db-schema/schema-types'
import type { MockTimeKeeper } from '../utils/time-keeper'

export interface BaseSeedOptions {
  db: DrizzleSQLiteDB
  timeKeeper: MockTimeKeeper
  size?: number
}

export class BaseSeed {
  protected db: DrizzleSQLiteDB
  protected timeKeeper: MockTimeKeeper
  protected size: number
  constructor(options: BaseSeedOptions) {
    this.db = options.db
    this.timeKeeper = options.timeKeeper
    this.size = options.size ?? 10
  }
}
