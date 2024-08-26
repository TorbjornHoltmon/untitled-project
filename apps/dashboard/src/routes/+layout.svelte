<script lang="ts">
  import Start from '$lib/components/Layout/Start.svelte'
  import '../app.css'
  import type { LayoutData } from './$types'
</script>

<main class="h-full bg-white">
  <main class="h-full">
    <!-- <Start /> -->
    Hello layout
    <slot />
  </main>
</main>
