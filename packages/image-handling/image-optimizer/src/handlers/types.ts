import type { ImageMeta } from 'image-meta'
import type { Sharp, Color, KernelEnum } from 'sharp'

export interface Handler {
  args: ((argument: string) => any)[]
  order?: number
  apply: (context: HandlerContext, pipe: Sharp, ...arguments_: any[]) => any
}

export interface HandlerContext {
  quality?: number
  fit?: 'contain' | 'cover' | 'fill' | 'inside' | 'outside'
  position?: number | string
  background?: Color
  enlarge?: boolean
  kernel?: keyof KernelEnum
  meta: ImageMeta
}
