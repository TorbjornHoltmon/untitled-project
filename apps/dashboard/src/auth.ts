import { parseServerEnv } from '$lib/env/server-env'
import { SvelteKitAuth } from '@auth/sveltekit'
import type { SvelteKitAuthConfig } from '@auth/sveltekit'
import GitHub from '@auth/sveltekit/providers/github'

export const { handle, signIn, signOut } = SvelteKitAuth(async (event) => {
  const env = parseServerEnv(event?.platform?.env)
  const authOptions: SvelteKitAuthConfig = {
    providers: [
      GitHub({
        clientId: env.GITHUB_ID,
        clientSecret: env.GITHUB_SECRET,
      }),
    ],
    secret: env.AUTH_SECRET,
    trustHost: true,
    callbacks: {
      async jwt({ account, token, user, profile, session, trigger }) {
        return token
      },
      async session({ newSession, session, token, user, trigger }) {
        return session
      },
      async signIn({ user, account, profile, email, credentials }) {
        return true
      },
    },
  }
  return authOptions
})
