import type { RequestEvent } from '@sveltejs/kit'

export function fallback({}: RequestEvent) {
  return new Response('hello world!' + new Date().toISOString())
}
