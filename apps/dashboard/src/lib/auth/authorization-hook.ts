import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'

export const authorizationHandle: Handle = async ({ event, resolve }) => {
  // Protect any routes under /authenticated
  if (event.url.pathname.startsWith('/authenticated')) {
    const session = await event.locals.auth()
    if (!session) {
      // Redirect to the signin page
      throw redirect(303, '/auth/signin')
    }
      session.user
  }

  // If the request is still here, just proceed as normally
  return resolve(event)
}
