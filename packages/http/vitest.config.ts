import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./test/helpers/setup-server.ts'],
    testTimeout: 200_000,
  },
})
