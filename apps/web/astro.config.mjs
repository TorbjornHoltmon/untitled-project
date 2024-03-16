import { defineConfig } from 'astro/config'
import cloudflare from '@astrojs/cloudflare'
import tailwind from '@astrojs/tailwind'
import vue from '@astrojs/vue'

// https://astro.build/config
export default defineConfig({
  output: 'server',
  adapter: cloudflare({
    mode: 'advanced',
  }),
  ssr: {
    noExternal: [/@untitled-project\/.*/],
  },
  // build: {
  //   inlineStylesheets: 'always',
  // },
  integrations: [tailwind(), vue()],
})
