import { R2BucketClient, type R2ClientOptions } from '@untitled-project/cloudflare-r2'
import { getHandlerKeys, optimizeImage, type OptimizerModifiers } from '@untitled-project/image-optimizer'
import sortKeys from 'sort-keys'

export interface OptimizeImageEndpointOptions {
  r2ClientOptions: R2ClientOptions
  request: Request
}

function parseModifiers(request: Request): OptimizerModifiers {
  const url = new URL(request.url)
  const modifiers: OptimizerModifiers = {}
  const handlerKeys = getHandlerKeys()
  for (const [key, value] of url.searchParams.entries()) {
    if (key === 'format') {
      modifiers[key] = value
      continue
    }
    if (key === 'f') {
      modifiers.format = value
      continue
    }
    if (handlerKeys.includes(key)) {
      modifiers[key as keyof OptimizerModifiers] = value
    }
  }
  return sortKeys(modifiers, { deep: false })
}

/**
 * Assumes that the request is a GET request with a URL that contains the path to the image.
 * The assumed path is api/images/{image-id}/{whatever}/{all-paths-are-used-as-id}/
 * queries are used to modify the image.
 */
export async function createOptimization(options: OptimizeImageEndpointOptions) {
  const { r2ClientOptions, request } = options

  const r2Client = new R2BucketClient(r2ClientOptions)

  const modifiers = parseModifiers(request)

  const url = new URL(request.url)

  const [_0, _1, ...rest] = url.pathname.slice(1).split('/')

  const path = rest.join('/')

  const appendedPath = []
  for (const [key, value] of Object.entries(modifiers)) {
    appendedPath.push(`${key}_${value}`)
  }

  const pathWithModifiers = appendedPath.length ? `${path}/${appendedPath.join('-')}` : path

  const r2Image = await r2Client.downloadFile(pathWithModifiers)

  if (r2Image?.Body && r2Image.ContentType) {
    return new Response(await r2Image.Body.transformToByteArray(), {
      status: 200,
      headers: {
        'content-type': r2Image.ContentType,
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=31536000, s-maxage=31536000, immutable',
      },
    })
  }

  const image = await r2Client.downloadFile(path)

  if (!image?.Body) {
    return new Response('', {
      status: 404,
      statusText: 'Not Found',
    })
  }

  const uintArray = await image.Body.transformToByteArray()
  const buffer = Buffer.from(uintArray)

  const optimizedImage = await optimizeImage({
    image: buffer,
    modifiers,
  })

  const contentType = modifiers?.format ? `image/${modifiers.format}` : image.ContentType

  await r2Client.uploadFile({
    file: optimizedImage,
    path: pathWithModifiers,
    // TODO: ensure content type is set
    contentType,
    cacheControl: 'public, max-age=31536000, s-maxage=31536000, immutable',
  })

  return new Response(optimizedImage, {
    headers: {
      // TODO: ensure content type is set
      contentType: contentType!,
      'Access-Control-Allow-Origin': '*',
      cacheControl: 'public, max-age=31536000, s-maxage=31536000, immutable',
    },
  })
}
