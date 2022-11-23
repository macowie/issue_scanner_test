import {default as axios} from 'axios'

export async function fetchUrl(url, config): Promise<{data}> {
  return axios.get(url, config)
}

export function is404(err): boolean {
  return axios.isAxiosError(err) && err.response?.status === 404
}

export function notBlank<TValue>(
  value: TValue | null | undefined
): value is TValue {
  if (value === null || value === undefined) return false
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const testDummy: TValue = value
  return true
}
