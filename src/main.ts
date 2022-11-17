import {getInput, setFailed, notice, info} from '@actions/core'

import {getTideliftRecommendations} from './tidelift_recommendation'
import {getCurrentIssue, IssueNotFoundError} from './issue'
import {createRecommendationCommentIfNeeded} from './comment'
import {getOctokit} from '@actions/github'

const ignoreIfAssigned = getInput('ignore-if-assigned')

function formatVulnerabilityLabel(vuln_id: VulnerabilityId): string {
  return `:yellow_circle: ${vuln_id}`
}

function formatHasRecommenationLabel(): string {
  return `:green_circle: has-recommendation`
}

export class VulnerabilityId {
  id: string

  constructor(str) {
    this.id = str.toUpperCase()
  }

  toString(): string {
    return this.id
  }
}

export function findMentionedVulnerabilities({title, body}): VulnerabilityId[] {
  const regex = /CVE-[\d]+-[\d]+/gi

  return Array.from(
    new Set(
      [title, body]
        .filter(field => typeof field === 'string')
        .flatMap(field => field.match(regex))
        .filter(field => field)
        .map(vuln_id => new VulnerabilityId(vuln_id))
    )
  )
}

export async function scanIssue(): Promise<string> {
  const octokit = getOctokit(getInput('repo-token'))
  const issue = getCurrentIssue(octokit)

  if (ignoreIfAssigned && issue.hasAssignees) {
    return 'No action being taken. Ignoring because one or more assignees have been added to the issue'
  }

  issue.refreshData()
  const mentionedVulns = findMentionedVulnerabilities(issue.data)

  if (mentionedVulns.length === 0) {
    return 'Did not find any vulnerabilities mentioned'
  }

  const recs = await getTideliftRecommendations(mentionedVulns)
  const labelsToAdd = mentionedVulns.map(formatVulnerabilityLabel)

  if (recs.length > 0) {
    labelsToAdd.push(formatHasRecommenationLabel())
  }

  for (const rec of recs) {
    await createRecommendationCommentIfNeeded(issue, rec)
  }

  await issue.addLabels(labelsToAdd)

  return `Found: ${mentionedVulns}; Recs: ${recs.map(r => r.vuln_id)}`
}

async function run(): Promise<void> {
  try {
    const message = await scanIssue()

    info(message)
  } catch (error) {
    if (error instanceof IssueNotFoundError) {
      notice('Could not find current issue. Skipping.')
    } else if (error instanceof Error) {
      setFailed(error)
    } else {
      setFailed(String(error))
    }
  }
}

run()
