import azure from '@azure/functions'

import { createOptimization } from '@untitled-project/r2-image-optimizer-node'

import { isValidationError } from 'zod-validation-error'
import { safeParseEnv } from './env-schema'

const { app, HttpResponse } = azure

app.http('images', {
  methods: ['GET'],
  route: '{*wildcard}',
  handler: async (request, context) => {
    try {
      const env = safeParseEnv()

      if (isValidationError(env)) {
        return new HttpResponse({
          status: 500,
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(env.message),
        })
      }

      const response = await createOptimization({
        r2ClientOptions: {
          bucket: env.BUCKET_NAME,
          cloudflareAccountId: env.CLOUDFLARE_ACCOUNT_ID,
          R2AccessKeyId: env.R2_ACCESS_KEY_ID,
          R2SecretAccessKey: env.SECRET_ACCESS_KEY,
        },
        request: new Request(request.url),
      })

      if (!response.body) {
        return new HttpResponse({
          status: 404,
        })
      }

      // Azure does not support streaming responses, so we need to buffer the response body
      const reader = response.body.getReader()

      const responseBodyArrayBuffer = await streamToArrayBuffer(reader)

      return new HttpResponse({
        body: responseBodyArrayBuffer,
        headers: response.headers,
        status: response.status,
      })
    } catch (error: unknown) {
      context.log('error', error)
      return new HttpResponse({
        status: 500,
        headers: {
          'Content-Type': 'text/plain',
        },
        body: JSON.stringify(error),
      })
    }
  },
})

async function streamToArrayBuffer(reader: ReadableStreamDefaultReader<Uint8Array>) {
  const chunks = []
  while (true) {
    const { done, value } = await reader.read()

    if (done) {
      break
    }

    for (const byte of value) {
      chunks.push(byte)
    }

    // chunks.push(...value)
  }

  return new Uint8Array(chunks)
}
