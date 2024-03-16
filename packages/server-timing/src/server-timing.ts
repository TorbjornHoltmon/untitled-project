import { nowMilliseconds } from '@untitled-project/utils'

export type ServerTimingEntry = {
  name: string
  description?: string
  duration: number
}

export type AddEntryFromPromiseParams<T> = {
  promise: () => Promise<T>
  name: string
  description?: string
}

export class ServerTiming {
  public entries: ServerTimingEntry[] = []

  public addEntry(entry: ServerTimingEntry) {
    this.entries.push(entry)
  }

  public addEntries(entries: ServerTimingEntry[]) {
    this.entries.push(...entries)
  }

  public async addEntryFromPromise<T>({ name, promise, description }: AddEntryFromPromiseParams<T>): Promise<T> {
    const startTime = nowMilliseconds()
    const result = await promise()
    const endTime = nowMilliseconds()
    this.addEntry({
      name,
      description,
      duration: endTime - startTime,
    })
    return result
  }

  public createServerTimingHeaderValue() {
    return this.entries
      .map(({ name, description, duration }) => {
        const descriptionString = description ? `;desc="${description}"` : ''
        return `${name};dur=${duration}${descriptionString}`
      })
      .join(', ')
  }

  public addServerTimingHeaderToResponse(res: Response) {
    res.headers.append('Server-Timing', this.createServerTimingHeaderValue())
  }

  public addServerTimingHeaderToHeaders(headers: Headers) {
    headers.append('Server-Timing', this.createServerTimingHeaderValue())
  }
}
