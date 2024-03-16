import type { Inngest } from 'inngest'
import { inngestClient } from './client'

// Stupid hack. Something is wrong with typings in inngest
type createFunction = Inngest['createFunction']

export const helloWorldFunction: ReturnType<createFunction> = inngestClient.createFunction(
  {
    id: 'hello-world',
    onFailure: async ({ error, event, step }) => {},
  },
  { event: 'test/hello.world' },
  async ({ event, step }) => {
    await step.sleep('wait-a-moment', '1s')
    await step.run('The first step is here', () => {
      return { body: 'Hello, Worldsssss!' }
    })

    const stepResult = await step.run('console.log2', () => {
      return { body: 'Hello, Worldsssss!' }
    })

    return { event, body: 'Hello, World! completed' }
  },
)
