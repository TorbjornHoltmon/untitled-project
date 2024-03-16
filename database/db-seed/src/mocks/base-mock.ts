import type { MockTimeKeeper } from '../utils/time-keeper'

export interface BaseMockOptions {
  timeKeeper: MockTimeKeeper
}

export class BaseMock {
  protected timeKeeper: MockTimeKeeper
  constructor(options: BaseMockOptions) {
    this.timeKeeper = options.timeKeeper
  }
}
