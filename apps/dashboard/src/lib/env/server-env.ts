import z from 'zod'
import { fromZodError } from 'zod-validation-error'

export const serverEnvSchema = z.object({
  // Auth
  // AUTH_SECRET: z.string(),
  // GITHUB_ID: z.string(),
  // GITHUB_SECRET: z.string(),
})

export type ServerEnv = z.infer<typeof serverEnvSchema>

export function parseServerEnv(env: unknown): ServerEnv {
  const result = serverEnvSchema.safeParse(env ?? {})
  if (!result.success) {
    const error = fromZodError(result.error, {
      prefix: 'Invalid server environment variables',
    })
    throw error
  }
  return result.data
}
