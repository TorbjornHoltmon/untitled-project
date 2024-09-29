// import { type Cart } from '@untitled-project/db'
// import { faker } from '@faker-js/faker'
// import { ulid } from 'ulidx'
// import { subYears } from 'date-fns'
// import type { BaseMock } from './base-mock'

// export interface CartMockOptions extends BaseMock {}

// export function cartMock(): Cart {
//   return {
//     id: ulid(),
//     active: faker.datatype.boolean({
//       probability: 0.95,
//     }),
//     createdAt: faker.date.recent().toISOString(),
//     updatedAt: faker.date.recent().toISOString(),
//   }
// }

// export class CartMock {
//   startDate: Date
//   constructor({ startDate }: SeedDatabaseOptions) {
//     this.startDate = startDate ?? subYears(new Date(), 1)
//   }
// }
