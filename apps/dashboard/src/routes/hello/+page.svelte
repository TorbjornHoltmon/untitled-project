<script lang="ts">
  import { createHighlighterCore, loadWasm } from 'shiki/core'
  import getWasm from 'shiki/wasm'
  import { bundledThemes } from 'shiki/themes'
  import { bundledLanguages } from 'shiki/langs'

  import json from '../../lib/json-test.json'

  import { onMount } from 'svelte'

  let jsonHtml: string | undefined

  onMount(async () => {
    console.log('onMount')
    await loadWasm(getWasm)
    const githubDarkDimmedTheme = await bundledThemes['github-dark-dimmed']()
    const jsonLang = await bundledLanguages.json()
    const highlighter = await createHighlighterCore({
      themes: [githubDarkDimmedTheme.default],
      langs: [jsonLang.default],
    })

    jsonHtml = highlighter.codeToHtml(JSON.stringify(json, null, 2), {
      lang: 'json',
      theme: 'github-dark-dimmed',
    })
  })
</script>

<div class="h-full flex">
  {#if jsonHtml}
    {@html jsonHtml}
  {/if}
</div>
