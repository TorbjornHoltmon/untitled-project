// See https://kit.svelte.dev/docs/types#app
// for information about these interfaces
declare global {
  namespace App {
    interface Platform {
      env?: {
        GITHUB_ID: string
        GITHUB_SECRET: string
        AUTH_SECRET: string
        KV: KVNamespace
      }
    }
    // interface Error {}
    // interface Locals {}
    // interface PageData {}
    // interface PageState {}
  }
}

export {}
