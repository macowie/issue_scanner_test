import {getInput, setFailed, notice, info} from '@actions/core'
import {getOctokit} from '@actions/github'
import * as dotenv from 'dotenv'

import {fetchTideliftRecommendations} from './tidelift_recommendation'
import {getCurrentIssue, IssueNotFoundError} from './issue'
import {createRecommendationCommentIfNeeded} from './comment'
import {findMentionedVulnerabilities, VulnerabilityId} from './vulnerability'

dotenv.config()

const ignoreIfAssigned = getInput('ignore-if-assigned')

function formatVulnerabilityLabel(vuln_id: VulnerabilityId): string {
  return `:yellow_circle: ${vuln_id}`
}

function formatHasRecommenationLabel(): string {
  return `:green_circle: has-recommendation`
}

export async function scanIssue(): Promise<string> {
  const githubToken = getInput('repo-token') || process.env.GITHUB_TOKEN
  const tideliftToken = getInput('tidelift-token') || process.env.TIDELIFT_TOKEN

  if (!githubToken) {
    return 'Could not initialize Github API Client'
  }

  const octokit = getOctokit(githubToken)
  const issue = getCurrentIssue(octokit)

  if (ignoreIfAssigned && issue.hasAssignees) {
    return 'No action being taken. Ignoring because one or more assignees have been added to the issue'
  }

  await issue.refreshData()

  const mentionedVulns = await findMentionedVulnerabilities(
    issue.searchableText,
    octokit
  )

  if (mentionedVulns.length === 0) {
    return 'Did not find any vulnerabilities mentioned'
  }

  let successMessage = `Found: ${mentionedVulns}`
  const labelsToAdd = mentionedVulns.map(formatVulnerabilityLabel)

  if (!tideliftToken) {
    info('No Tidelift token provided, skipping recommendation scan.')
  } else {
    const recs = await fetchTideliftRecommendations(
      mentionedVulns,
      tideliftToken
    )
    if (recs.length > 0) {
      labelsToAdd.push(formatHasRecommenationLabel())
    }

    for (const rec of recs) {
      await createRecommendationCommentIfNeeded(issue, rec)
    }
    successMessage += `; Recs: ${recs.map(r => r.vuln_id)}`
  }

  await issue.addLabels(labelsToAdd)

  return successMessage
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
