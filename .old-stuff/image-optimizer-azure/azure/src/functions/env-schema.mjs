import z from 'zod';
import { fromZodError } from 'zod-validation-error';

const envSchema = z.object({
  BUCKET_NAME: z.string(),
  R2_ACCESS_KEY_ID: z.string(),
  SECRET_ACCESS_KEY: z.string(),
  CLOUDFLARE_ACCOUNT_ID: z.string()
});
function safeParseEnv() {
  const env = process.env;
  const parsedEnv = envSchema.safeParse(env);
  if (parsedEnv.success) {
    return parsedEnv.data;
  }
  return fromZodError(parsedEnv.error);
}

export { safeParseEnv };
