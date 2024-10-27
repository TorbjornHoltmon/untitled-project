import { buildCommand } from '@stricli/core'

export const subdirCommand = buildCommand({
  loader: async () => import('./impl.js'),
  parameters: {
    positional: {
      kind: 'tuple',
      parameters: [],
    },
  },
  docs: {
    brief: 'Command in subdirectory',
  },
})
