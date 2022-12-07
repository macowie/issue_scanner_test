import {concurrently, notBlank} from './utils'
import {Configuration} from './configuration'
import {Vulnerability} from './vulnerability'
import {Issue} from './issue'
import {createRecommendationCommentIfNeeded} from './comment'
import {TideliftClient} from './tidelift_client'
import {GithubClient} from './github_client'
import {info} from '@actions/core'
import {TideliftRecommendation} from './tidelift_recommendation'

export class Scanner {
  config: Configuration
  github: GithubClient
  tidelift?: TideliftClient

  constructor({config, github, tidelift}: Partial<Scanner> = {}) {
    this.config = config || new Configuration()
    this.github = github || new GithubClient(this.config.github_token)

    this.tidelift = tidelift
    if (this.config.tidelift_token) {
      this.tidelift ||= new TideliftClient(this.config.tidelift_token)
    }
  }

  static statuses = {
    no_issue_data: context => `Could not get issue data for ${context}`,
    ignored_assigned: () =>
      `No action being taken. Ignoring because one or more assignees have been added to the issue`,
    no_vulnerabilities: () => 'Did not find any vulnerabilities mentioned',
    success: (vulns, recs) =>
      `Detected mentions of: ${vulns}
       With recommendations on: ${recs.map(r => r.vulnerability)}`
  }

  async perform(issue: Issue): Promise<string> {
    try {
      issue.data = await this.github.getIssue(issue)
    } catch {
      return Scanner.statuses.no_issue_data(issue.context)
    }

    if (this.config.ignore_if_assigned && issue.hasAssignees) {
      return Scanner.statuses.ignored_assigned()
    }

    const vulnerabilities = await findMentionedVulnerabilities(
      issue.searchableText,
      this.github
    )
    const recommendations: TideliftRecommendation[] = []

    if (vulnerabilities.length === 0) {
      return Scanner.statuses.no_vulnerabilities()
    }

    const labelsToAdd = vulnerabilities.map(vuln =>
      this.config.templates.vuln_label(vuln.id)
    )

    if (!this.config.tidelift_token) {
      info('No Tidelift token provided, skipping recommendation scan.')
    } else {
      this.tidelift = new TideliftClient(this.config.tidelift_token)

      recommendations.concat(
        await this.tidelift.fetchRecommendations(vulnerabilities)
      )

      if (recommendations.length > 0) {
        labelsToAdd.push(this.config.templates.has_recommendation_label())
      }

      for (const rec of recommendations) {
        await createRecommendationCommentIfNeeded(
          issue,
          rec,
          this.github,
          this.config.templates.recommendation_body
        )
      }
    }

    await this.github.addLabels(issue, labelsToAdd)

    return Scanner.statuses.success(vulnerabilities, recommendations)
  }
}

export async function findMentionedVulnerabilities(
  fields: string[],
  github: GithubClient | void
): Promise<Vulnerability[]> {
  const cve_ids = new Set(fields.flatMap(scanCve))
  const ghsa_ids = new Set(fields.flatMap(scanGhsa))

  if (github && ghsa_ids.size > 0) {
    const translated_ids = await concurrently<string, string>(
      [...ghsa_ids],
      async ghsa_id => github.getCveForGhsa(ghsa_id)
    )

    for (const cve_id of translated_ids) {
      cve_ids.add(cve_id)
    }
  }

  return [...cve_ids].map(id => new Vulnerability(id))
}

export function scanGhsa(text: string): string[] {
  const regex = /GHSA-\w{4}-\w{4}-\w{4}/gi

  return (String(text).match(regex) || []).filter(notBlank)
}

export function scanCve(text: string): string[] {
  const regex = /CVE-\d{4}-\d+/gi

  return (String(text).match(regex) || [])
    .filter(notBlank)
    .map(str => str.toUpperCase())
}
