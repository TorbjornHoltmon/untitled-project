import { describe, expect, test } from 'vitest'
import { NewHttpClient } from '../src/client'
import { HttpTimeoutError } from '../src/timeout'
import { timeoutEndpoint } from './helpers/setup-server'

describe('Retry tests', () => {
  test('Test timeout', async () => {
    try {
      const httpClient = new NewHttpClient({
        debug: true,
      })

      await httpClient.get(timeoutEndpoint)
    } catch (error) {
      expect(error).instanceOf(HttpTimeoutError)
    }
  })
})
