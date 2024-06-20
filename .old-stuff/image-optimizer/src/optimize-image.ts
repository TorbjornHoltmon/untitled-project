import { imageMeta as getImageMeta, type ImageMeta } from 'image-meta'
import Sharp from 'sharp'
import { applyHandler, getHandler, preserveAspectRatio, type HandlerName } from './handlers/utils'

// https://sharp.pixelplumbing.com/#formats
// (gif and svg are not supported as output)
const SUPPORTED_FORMATS = new Set(['jpeg', 'png', 'webp', 'avif', 'tiff', 'heif', 'gif', 'heic'])

export type OptimizerModifiers = Partial<Record<HandlerName | 'f' | 'format' | 'a' | 'animated', string>>
export interface OptimizeOptions {
  modifiers: OptimizerModifiers
  image: Buffer
}

export function optimizeImage({ modifiers, image }: OptimizeOptions) {
  // Detect source image meta
  let imageMeta: ImageMeta
  try {
    imageMeta = getImageMeta(image)
  } catch {
    throw new Error('Invalid image', {
      cause: {
        statusText: `IPX_INVALID_IMAGE`,
        message: `Cannot parse image metadata`,
      },
    })
  }

  // Determine format
  let mFormat = modifiers.f || modifiers.format
  if (mFormat === 'jpg') {
    mFormat = 'jpeg'
  }

  const format =
    mFormat && SUPPORTED_FORMATS.has(mFormat)
      ? mFormat
      : SUPPORTED_FORMATS.has(imageMeta.type || '') // eslint-disable-line unicorn/no-nested-ternary
      ? imageMeta.type
      : 'jpeg'

  // Experimental animated support
  // https://github.com/lovell/sharp/issues/2275
  const animated = modifiers.animated !== undefined || modifiers.a !== undefined || format === 'gif'

  let sharp = Sharp(image, { animated })

  // TODO: Preserve orientation with imageMeta.orientation

  // Preserve aspect ratio
  const { width, height } = preserveAspectRatio(imageMeta, {
    width: modifiers.width ? Number(modifiers.width) : undefined,
    height: modifiers.height ? Number(modifiers.height) : undefined,
  })
  // Resolve modifiers to handlers and sort
  const handlers = Object.entries({
    ...modifiers,
    width: String(width),
    height: String(height),
  })
    .map(([name, arguments_]) => {
      return { handler: getHandler(name as HandlerName), name, args: arguments_ }
    })
    .filter((h) => h.handler)
    .sort((a, b) => {
      const aKey = (a.handler.order || a.name || '').toString()
      const bKey = (b.handler.order || b.name || '').toString()
      return aKey.localeCompare(bKey)
    })

  // Apply handlers
  const handlerContext: any = { meta: imageMeta }
  for (const h of handlers) {
    sharp = applyHandler(handlerContext, sharp, h.handler, h.args) || sharp
  }

  // Apply format
  if (SUPPORTED_FORMATS.has(format || '')) {
    sharp = sharp.toFormat(format as any, {
      quality: handlerContext.quality,
      progressive: format === 'jpeg',
    })
  }

  // Convert to buffer
  return sharp.toBuffer()
}
