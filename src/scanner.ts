import {concurrently, notBlank} from './utils'
import {Configuration} from './configuration'
import {Vulnerability} from './vulnerability'
import {Issue} from './issue'
import {createRecommendationCommentIfNeeded} from './comment'
import {TideliftClient} from './tidelift_client'
import {GithubClient} from './github_client'
import {info} from '@actions/core'

export class Scanner {
  config: Configuration
  github: GithubClient
  tidelift?: TideliftClient

  constructor(options: Configuration | void) {
    this.config = new Configuration(options)
    this.github = new GithubClient(this.config.github_token)
  }

  async perform(issue: Issue): Promise<string> {
    await issue.fetchData(this.github)

    if (this.config.ignore_if_assigned && issue.hasAssignees) {
      return 'No action being taken. Ignoring because one or more assignees have been added to the issue'
    }

    const mentionedVulns = await findMentionedVulnerabilities(
      issue.searchableText,
      this.github
    )

    if (mentionedVulns.length === 0) {
      return 'Did not find any vulnerabilities mentioned'
    }

    const labelsToAdd = mentionedVulns.map(vuln =>
      this.config.templates.vuln_label(vuln.id)
    )

    let msg = `Found mentions of: ${mentionedVulns}`

    if (!this.config.tidelift_token) {
      info('No Tidelift token provided, skipping recommendation scan.')
    } else {
      this.tidelift = new TideliftClient(this.config.tidelift_token)

      const recommendations = await this.tidelift.fetchRecommendations(
        mentionedVulns
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

      msg += `\nWith recommendations on: ${recommendations.map(
        r => r.vulnerability
      )}`
    }

    await this.github.addLabels(issue, labelsToAdd)

    return msg
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
