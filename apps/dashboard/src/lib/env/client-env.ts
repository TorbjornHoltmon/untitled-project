import z from 'zod'
import { fromZodError } from 'zod-validation-error'
import { PUBLIC_KEY } from '$env/static/public'

export const serverEnvSchema = z.object({})

export type ClientEnv = z.infer<typeof serverEnvSchema>

export function getClientEnv(): ClientEnv {
  const result = serverEnvSchema.safeParse({
    PUBLIC_KEY,
  })
  if (!result.success) {
    const error = fromZodError(result.error, {
      prefix: 'Invalid environment variables',
    })
    throw error
  }
  return result.data
}
