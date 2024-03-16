import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { it } from 'vitest'
import { optimizeImage } from '../src'

it('decrease height, make webp', async () => {
  const dirname = path.dirname(fileURLToPath(import.meta.url))
  const jpgImage = await readFile(dirname + '/assets/1.JPG')
  const result = await optimizeImage({
    modifiers: {
      height: '300',
      format: 'png',
      quality: '100',
      rotate: '90',
      flip: 'true',
      fit: 'fill',
      position: 'bottom',
    },
    image: jpgImage,
  })
  const id = crypto.randomUUID().slice(0, 3)
  await writeFile(dirname + `/results/${id}.png`, result)
})
