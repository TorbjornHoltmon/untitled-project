import { defineConfig } from 'vite'
import { globby } from 'globby'

const files = await globby('src/**/*.ts')

export default defineConfig({
  ssr: {
    noExternal: ['@untitled-project/image-optimizer'],
    external: ['@azure/functions', 'sharp'],
    target: 'node',
  },
  build: {
    ssr: true,
    target: 'esnext',
    emptyOutDir: true,
    outDir: 'azure/src/functions',
    rollupOptions: {
      output: {
        entryFileNames: `[name].mjs`,
        chunkFileNames: `modules/[name].mjs`,
      },
      input: files,
    },
  },
})
