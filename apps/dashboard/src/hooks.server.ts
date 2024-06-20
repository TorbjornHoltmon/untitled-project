import type { Handle } from '@sveltejs/kit'
import { handle as authJSHandle } from './auth'
import { sequence } from '@sveltejs/kit/hooks'

// export const handle: Handle = sequence(authJSHandle)
