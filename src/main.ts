import {getInput, setFailed} from '@actions/core'
import * as github from '@actions/github'
import {Context} from '@actions/github/lib/context'

import {
  TideliftRecommendation,
  getTideliftRecommendations
} from './tidelift_recommendation'

const myToken = getInput('repo-token')
const octokit = github.getOctokit(myToken)

export type VulnerabilityId = string
export type IssueNumber = number
export type RepoOwner = string
export type RepoName = string

async function getIssue(
  repoOwner: RepoOwner,
  repoName: RepoName,
  issueNumber: IssueNumber
): Promise<object> {
  return octokit.rest.issues.get({
    owner: repoOwner,
    repo: repoName,
    issue_number: issueNumber
  })
}

async function addLabels(
  owner: RepoOwner,
  repo: RepoName,
  issue_number: IssueNumber,
  labels: string[]
): Promise<object> {
  return octokit.rest.issues.addLabels({owner, repo, issue_number, labels})
}

async function addComment(
  owner: RepoOwner,
  repo: RepoName,
  issue_number: IssueNumber,
  body: string
): Promise<object> {
  return octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number,
    body
  })
}

function issueHasBeenAssigned(issue): boolean {
  return issue.data.assignees.length !== 0
}

function getIssueNumber(context: Context): IssueNumber | undefined {
  const possibleNumber =
    getInput('issue-number') ||
    context.payload?.issue?.number ||
    context.payload?.pull_request?.number

  if (possibleNumber) return Number(possibleNumber)
}

function findMentionedCves(issue): VulnerabilityId[] {
  const regex = /CVE-[\d]+-[\d]+/gi
  const searchFields = ['body', 'title']

  return Array.from(
    new Set(
      searchFields
        .map(field => issue.data[field])
        .filter(field => typeof field === 'string')
        .flatMap(field => field.match(regex))
        .filter(field => field)
    )
  )
}

function formatLabelName(cve: VulnerabilityId): string {
  return `:yellow_circle: ${cve.toUpperCase()}`
}

function formatRecommendationText(
  recommendation: TideliftRecommendation
): string {
  return `:wave: Looks like you're reporting ${
    recommendation.vuln_id
  }.\n\n${JSON.stringify(recommendation)}`
}

function formatRecommendationsComment(recs: TideliftRecommendation[]): string {
  return recs.map(formatRecommendationText).join('\n\n')
}

async function scanIssue(): Promise<string> {
  const repoName = github.context?.payload?.repository?.name as RepoName
  const repoOwner = github.context?.payload?.repository?.owner
    ?.login as RepoOwner
  // eslint-disable-next-line prefer-const
  let ignoreIfAssigned = false

  const issueNumber = getIssueNumber(github.context)

  if (issueNumber === undefined) {
    return 'No action being taken. Ignoring because issueNumber was not identified'
  }

  // Refresh for latest changes
  // eslint-disable-next-line prefer-const
  let issue = await getIssue(repoOwner, repoName, issueNumber)

  if (ignoreIfAssigned && issueHasBeenAssigned(issue)) {
    return 'No action being taken. Ignoring because one or more assignees have been added to the issue'
  }

  const mentionedCves = findMentionedCves(issue)

  if (mentionedCves.length === 0) {
    return 'Did not find any CVEs mentioned'
  }

  await addLabels(
    repoOwner,
    repoName,
    issueNumber,
    mentionedCves.map(formatLabelName)
  )

  const recs = await getTideliftRecommendations(mentionedCves)

  if (recs.length === 0) {
    return `Did not find any Tidelift recommendations for CVEs: ${mentionedCves}`
  }

  await addComment(
    repoOwner,
    repoName,
    issueNumber,
    formatRecommendationsComment(recs)
  )

  return `Found: ${mentionedCves}; Recs: ${recs}`
}

async function run(): Promise<void> {
  try {
    await scanIssue()
  } catch (error) {
    let msg
    if (error instanceof Error) {
      msg = error.message
    } else {
      msg = error
    }
    setFailed(msg)
  }
}

run()
