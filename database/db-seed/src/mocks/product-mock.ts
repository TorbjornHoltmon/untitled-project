import { faker } from '@faker-js/faker'
import type { Product, Variant } from '@untitled-project/db-schema'
import { BaseMock, type BaseMockOptions } from './base-mock'

export interface ProductMockOptions extends BaseMockOptions {}
export class ProductMock extends BaseMock {
  public buildProduct(): Product {
    this.timeKeeper.incrementDate()
    return {
      id: this.timeKeeper.getUlid(),
      title: faker.commerce.productName(),
      createdAt: this.timeKeeper.currentDate.toISOString(),
      updatedAt: this.timeKeeper.getUpTo14DaysFuture(),
    }
  }

  public buildVariant(productId: string): Variant {
    this.timeKeeper.incrementDate()
    return {
      id: this.timeKeeper.getUlid(),
      productId,
      skuId: this.timeKeeper.getUlid(),
      title: faker.commerce.productName(),
      createdAt: this.timeKeeper.currentDate.toISOString(),
      updatedAt: this.timeKeeper.getUpTo14DaysFuture(),
      price: faker.number.int({
        max: 10_000,
        min: 1,
      }),
    }
  }

  public buildProductAndVariants() {
    const product = this.buildProduct()
    const variants: Variant[] = []

    for (let i = 0; i < faker.number.int({ max: 10, min: 1 }); i++) {
      variants.push(this.buildVariant(product.id))
    }

    return {
      product,
      variants,
    }
  }
}
