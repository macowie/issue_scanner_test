import {getOctokit} from '@actions/github'
import {issueContext} from './issue'

import type {GitHub} from '@actions/github/lib/utils'
import type {RestEndpointMethodTypes} from '@octokit/plugin-rest-endpoint-methods'
import type {GraphQlQueryResponseData} from '@octokit/graphql'

export type issueData =
  RestEndpointMethodTypes['issues']['get']['response']['data']
export type commentData =
  RestEndpointMethodTypes['issues']['getComment']['response']['data']
export type commentsData =
  RestEndpointMethodTypes['issues']['listComments']['response']['data']

export class GithubClient {
  octokit: InstanceType<typeof GitHub>

  constructor(token) {
    this.octokit = getOctokit(token)
  }

  async graphql({query, ...options}): Promise<GraphQlQueryResponseData> {
    return this.octokit.graphql({query, ...options})
  }

  async getCveForGhsa(ghsa_id: string): Promise<string | undefined> {
    const {securityAdvisory} = await this.graphql({
      query: `query advisoryIds($ghsa_id:String!) {
        securityAdvisory(ghsaId: $ghsa_id) {
           identifiers{
             type
             value
           }
         }        
       }`,
      ghsa_id
    })

    return securityAdvisory.identifiers.find(i => i['type'] === 'CVE')?.value
  }

  async getIssue(context: issueContext): Promise<issueData> {
    const {data} = await this.octokit.rest.issues.get(context)

    return data
  }

  async listComments(context: issueContext): Promise<commentsData> {
    const {data} = await this.octokit.rest.issues.listComments(context)

    return data
  }

  async addComment(
    context: issueContext,
    body: string
  ): Promise<
    RestEndpointMethodTypes['issues']['createComment']['response']['data']
  > {
    const {data} = await this.octokit.rest.issues.createComment({
      ...context,
      body
    })

    return data
  }

  async addLabels(
    context: issueContext,
    labels: string[]
  ): Promise<
    RestEndpointMethodTypes['issues']['addLabels']['response']['data']
  > {
    const {data} = await this.octokit.rest.issues.addLabels({
      ...context,
      labels
    })

    return data
  }
}
