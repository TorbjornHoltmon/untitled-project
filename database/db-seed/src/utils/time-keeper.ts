import { addDays, addMinutes, subYears } from 'date-fns'
import { faker } from '@faker-js/faker'
import { ulid } from 'ulidx'

export interface MockTimeKeeperOptions {
  /**
   * Some date in the past. Does not need to be in the past. But it should.
   * Records will be created historically from this date.
   * Meaning:
   *
   * A cart could have products in it, that are technically in the future.
   * Which would be impossible in real life.
   *
   * __Defaults to two year ago.__
   */
  startDate?: Date
}

export class MockTimeKeeper {
  public currentDate: Date

  constructor(options: MockTimeKeeperOptions) {
    this.currentDate = options.startDate ?? subYears(new Date(), 2)
  }

  public incrementDate() {
    this.currentDate = addMinutes(
      this.currentDate,
      faker.number.int({
        max: 3,
        min: 1,
      }),
    )
  }

  public getUlid() {
    return ulid(this.currentDate.getTime())
  }

  public getUpTo14DaysFuture() {
    return addDays(this.currentDate, faker.number.int({ max: 14, min: 1 })).toISOString()
  }
}
