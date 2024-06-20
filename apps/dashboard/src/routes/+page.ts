import type { PageLoad } from './$types'

export const load: PageLoad = ({ fetch }) => {
  return {
    post: {
      title: `Title`,
      content: `Content`,
    },
  }
}
