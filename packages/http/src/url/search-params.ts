export type SearchParamsInit = string | string[][] | Record<string, string> | URLSearchParams | undefined

export type SearchParamsOptions =
  | SearchParamsInit
  | Record<string, string | number | boolean>
  | Array<Array<string | number | boolean>>

export function createSearchParams(searchParams: SearchParamsOptions): string {
  if (typeof searchParams === 'string') {
    const stringSearchParams = searchParams.replace(/^\?/, '')
    return '?' + stringSearchParams
  }
  // Search params supports all the types of CreateSearchParamsOption, but the type definition is wrong.
  const stringSearchParams = new URLSearchParams(searchParams as unknown as SearchParamsInit).toString()
  return '?' + stringSearchParams
}
