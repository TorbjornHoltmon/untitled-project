import { serve } from 'inngest/edge'
import { inngestClient } from './client'
import { helloWorldFunction } from './hello-world-function'

export const endpoint = serve({
  client: inngestClient,
  functions: [helloWorldFunction],
})
