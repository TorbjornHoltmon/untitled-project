import { afterAll, afterEach, beforeAll } from 'vitest'
import { wait } from '@untitled-project/utils'

import { createAdaptorServer } from '@hono/node-server'
import { Hono } from 'hono'
const app = new Hono()

export const timeoutEndpoint = 'http://127.0.0.1:4321/timeout'

app.all('/timeout', async (c) => {
  await wait(20_000)
  return new Response('', {
    status: 200,
  })
})

const server = createAdaptorServer(app)

// Start server before all tests
beforeAll(() => {
  server.listen('4321')
})

//  Close server after all tests
afterAll(() => {
  server.close()
})
