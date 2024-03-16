type HttpTimeoutOptions = {
  timeout?: number
}

export class HttpTimeoutError extends Error {}

export class HttpTimeout {
  timeout: number
  timeoutId?: NodeJS.Timeout
  constructor(config: HttpTimeoutOptions = {}) {
    this.timeout = config.timeout || 15_000
    this.timeoutId = undefined
  }

  get start(): Promise<HttpTimeoutError> {
    return new Promise((resolve) => {
      this.timeoutId = setTimeout(() => {
        resolve(new HttpTimeoutError())
      }, this.timeout)
    })
  }

  clear() {
    this.timeoutId && clearTimeout(this.timeoutId)
  }
}
