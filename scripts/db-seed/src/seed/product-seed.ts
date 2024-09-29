import * as schema from '@untitled-project/db'
import { ProductMock } from '../mocks/product-mock'
import { BaseSeed, type BaseSeedOptions } from './base-seed'
export interface SeedProductOptions extends BaseSeedOptions {}

export class SeedProducts extends BaseSeed {
  protected productMock: ProductMock
  constructor(options: SeedProductOptions) {
    super(options)
    this.productMock = new ProductMock(options)
  }

  public async seedProducts() {
    await this.db.transaction(async (tx) => {
      for (let i = 0; i < this.size; i++) {
        const { product, variants } = this.productMock.buildProductAndVariants()

        await tx.insert(schema.product).values(product)
        for (const variant of variants) {
          await tx.insert(schema.variant).values(variant)
        }
      }
    })
  }
}
