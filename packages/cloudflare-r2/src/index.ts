import { z } from 'zod'
import { fromZodError } from 'zod-validation-error'
import { S3Client, PutObjectCommand, type PutObjectCommandInput, GetObjectCommand, NoSuchKey } from '@aws-sdk/client-s3'

const R2ClientOptionsSchema = z.object({
  cloudflareAccountId: z.string(),
  R2AccessKeyId: z.string(),
  R2SecretAccessKey: z.string(),
  bucket: z.string(),
})

export type R2ClientOptions = z.infer<typeof R2ClientOptionsSchema>

type UploadFileOptions = {
  file: PutObjectCommandInput['Body']
  path: string
  /**
   * @default 'public, max-age=31536000, s-maxage=31536000, immutable'
   */
  cacheControl?: string
  contentType?: string
}

export class R2BucketClient {
  private client: S3Client
  private bucket: string
  constructor(options: R2ClientOptions) {
    const parsedOptions = R2ClientOptionsSchema.safeParse(options)

    if (!parsedOptions.success) {
      const parsedError = fromZodError(parsedOptions.error, {
        prefix: 'Invalid R2BucketClient options',
      })
      throw new Error(parsedError.message)
    }
    const { cloudflareAccountId, R2AccessKeyId, R2SecretAccessKey, bucket } = parsedOptions.data

    this.client = new S3Client({
      region: 'auto',
      endpoint: `https://${cloudflareAccountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: R2AccessKeyId,
        secretAccessKey: R2SecretAccessKey,
      },
    })
    this.bucket = bucket
  }

  public async uploadFile({ file, path, cacheControl, contentType }: UploadFileOptions): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Body: file,
        Bucket: this.bucket,
        Key: path,
        CacheControl: cacheControl ?? 'public, max-age=31536000, s-maxage=31536000, immutable',
        ContentType: contentType,
      }),
    )
  }

  public async downloadFile(path: string) {
    try {
      const res = await this.client.send(
        new GetObjectCommand({
          Bucket: this.bucket,
          Key: path,
        }),
      )
      if (!res.Body) {
        return undefined
      }

      return res
    } catch (error) {
      if (error instanceof NoSuchKey) {
        return undefined
      }
      throw error
    }
  }
}
