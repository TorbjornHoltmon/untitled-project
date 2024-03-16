import type { RequestEvent } from '@sveltejs/kit'

export function GET({}: RequestEvent) {
  return new Response('hello world!' + new Date().toISOString())
}
