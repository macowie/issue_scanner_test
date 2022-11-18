import {default as axios} from 'axios'

export async function fetchUrl(url, config): Promise<{data}> {
  return axios.get(url, config)
}

export function is404(err): boolean {
  return axios.isAxiosError(err) && err.response?.status === 404
}