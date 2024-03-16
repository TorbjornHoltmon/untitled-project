import type { Sharp } from 'sharp'
import type { ImageMeta } from 'image-meta'
import type { Handler, HandlerContext } from './types'
import * as Handlers from './handlers'

export function parseArgs(arguments_: string, mappers: ((...args: any[]) => any)[]) {
  const vargs = arguments_.split('_')
  return mappers.map((v, index) => {
    return v(vargs[index])
  })
}

export type HandlerName = keyof typeof Handlers

export function getHandlerKeys() {
  return Object.keys(Handlers) as string[]
}

export function getHandler(key: HandlerName): Handler {
  // eslint-disable-next-line import/namespace
  return Handlers[key]
}

export function applyHandler(context: HandlerContext, pipe: Sharp, handler: Handler, argumentsString: string) {
  const arguments_ = handler.args ? parseArgs(argumentsString, handler.args) : []
  return handler.apply(context, pipe, ...arguments_)
}

export function preserveAspectRatio(
  sourceDimensions: ImageMeta,
  desiredDimensions: { width?: number; height?: number },
) {
  const { width, height } = desiredDimensions
  const { width: sourceWidth, height: sourceHeight } = sourceDimensions

  if (!sourceWidth || !sourceHeight) {
    return { width, height }
  }

  if (width && height) {
    return clampDimensionsPreservingAspectRatio(sourceDimensions, { width, height })
  }

  const aspectRatio = sourceWidth / sourceHeight

  if (width && !height) {
    return { width, height: Math.round(width / aspectRatio) }
  }

  if (!width && height) {
    return { width: Math.round(height * aspectRatio), height }
  }

  return { width, height }
}

export function clampDimensionsPreservingAspectRatio(
  sourceDimensions: ImageMeta,
  desiredDimensions: { width: number; height: number },
) {
  const desiredAspectRatio = desiredDimensions.width / desiredDimensions.height
  let { width, height } = desiredDimensions
  if (sourceDimensions.width && width > sourceDimensions.width) {
    width = sourceDimensions.width
    height = Math.round(sourceDimensions.width / desiredAspectRatio)
  }
  if (sourceDimensions.height && height > sourceDimensions.height) {
    height = sourceDimensions.height
    width = Math.round(sourceDimensions.height * desiredAspectRatio)
  }

  return { width, height }
}
