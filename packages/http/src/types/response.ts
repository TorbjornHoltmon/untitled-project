export interface RetailorHttpResponse extends Response {
  json: <T = unknown>() => Promise<T>
}
