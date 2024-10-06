import { Hono } from 'hono'
import type { HonoApiContext } from './api'

const productsApi = new Hono<HonoApiContext>().get('/', (c) => {
  return c.json({ now: new Date().toISOString(), name: 'John Doe' })
})

export { productsApi }
