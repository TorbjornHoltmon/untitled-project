import adapter from '@sveltejs/adapter-cloudflare'
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte'
import type { Config } from '@sveltejs/kit'

const config: Config = {
  // Consult https://kit.svelte.dev/docs/integrations#preprocessors
  // for more information about preprocessors
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      fallback: 'spa',
      routes: {
        include: ['/*'],
        exclude: ['<all>'],
      },
      platformProxy: {
        experimentalJsonConfig: false,
        persist: false,
      },
    }),
  },
}

export default config
