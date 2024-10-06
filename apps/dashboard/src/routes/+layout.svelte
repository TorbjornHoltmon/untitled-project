<script lang="ts">
  import Layout from '$lib/components/Layout/Layout.svelte'
  import '../app.css'
</script>

<main class="h-full bg-white">
  <main class="h-full">
    <Layout />
    Hello layout
    <slot />
  </main>
</main>
