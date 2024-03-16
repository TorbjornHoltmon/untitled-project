import type { APIContext } from 'astro'
import { endpoint } from '@untitled-project/inngest'

export function ALL({ request }: APIContext) {
  return endpoint(request)
}
