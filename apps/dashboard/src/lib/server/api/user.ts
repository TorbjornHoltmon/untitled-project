import { Hono } from 'hono'
import type { HonoApiContext } from './api'

const userApi = new Hono<HonoApiContext>().get('/', (c) => {
  return c.json({ now: new Date().toISOString(), name: 'John Doe' })
})

export { userApi }
