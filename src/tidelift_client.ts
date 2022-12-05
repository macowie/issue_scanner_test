import {default as axios} from 'axios'
import {TideliftRecommendation} from './tidelift_recommendation'
import {concurrently} from './utils'
import {Vulnerability} from './vulnerability'

export class TideliftClient {
  token: string
  client

  constructor(token: string) {
    this.token = token
    this.client = axios.create({
      baseURL: 'https://api.tidelift.com/external-api/v1',
      headers: {
        Authorization: `Bearer ${token}`
      },
      validateStatus: status =>
        (status >= 200 && status < 300) || status === 404
    })
  }

  async fetchRecommendation(
    vuln: Vulnerability
  ): Promise<TideliftRecommendation | undefined> {
    const response = await this.client.get(
      `/vulnerability/${vuln.id}/recommendation`
    )

    if (response.status === 404) {
      return
    }

    return new TideliftRecommendation(vuln, response.data)
  }

  async fetchRecommendations(
    vulns: Vulnerability[]
  ): Promise<TideliftRecommendation[]> {
    return await concurrently(vulns, async vuln =>
      this.fetchRecommendation(vuln)
    )
  }
}
