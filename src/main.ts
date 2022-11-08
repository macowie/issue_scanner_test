import {getInput, setFailed} from '@actions/core'
import * as github from '@actions/github'
import {Context as GithubContext} from '@actions/github/lib/context'

import {
  TideliftRecommendation,
  getTideliftRecommendations
} from './tidelift_recommendation'

export type VulnerabilityId = string
export type IssueNumber = number
export type RepoOwner = string
export type RepoName = string
export type IssueContext = {
  owner: RepoOwner
  repo: RepoName
  issue_number: IssueNumber
}

const myToken = getInput('repo-token')
const octokit = github.getOctokit(myToken)

async function getIssue(issueContext: IssueContext): Promise<object> {
  return octokit.rest.issues.get(issueContext)
}

async function addLabels(
  issueContext: IssueContext,
  labels: string[]
): Promise<object> {
  return octokit.rest.issues.addLabels({...issueContext, labels})
}

async function addComment(
  issueContext: IssueContext,
  body: string
): Promise<object> {
  return octokit.rest.issues.createComment({
    ...issueContext,
    body
  })
}

function issueHasBeenAssigned(issue): boolean {
  return issue.data.assignees.length !== 0
}

function getIssueNumber(context: GithubContext): IssueNumber {
  const possibleNumber =
    getInput('issue-number') ||
    context.payload?.issue?.number ||
    context.payload?.pull_request?.number

  if (possibleNumber) return Number(possibleNumber)

  throw Error('Could not determine current issue')
}

function getIssueContext(context: GithubContext): IssueContext {
  const repo = context.payload?.repository?.name
  const owner = context.payload?.repository?.owner?.login
  const issue_number = getIssueNumber(context)

  if (repo && owner && issue_number) return {repo, owner, issue_number}

  throw Error('Could not determine current issue')
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

async function createRecommendationCommentIfNeeded(
  issueContext: IssueContext,
  rec: TideliftRecommendation
): Promise<object | undefined> {
  const comments = await octokit.rest.issues.listComments(issueContext)

  const botComments = comments.data.filter(comment =>
    isBotReportComment(comment, rec.vuln_id)
  )

  if (botComments.length === 0)
    return addComment(issueContext, formatRecommendationText(rec))
}

function isBotReportComment(comment, vuln_id: VulnerabilityId): boolean {
  const actionsBot = 'github-actions[bot]'
  return (
    comment.user.login === actionsBot &&
    comment.body &&
    comment.body.match(vuln_id)
  )
}

async function scanIssue(): Promise<string> {
  const issueContext = getIssueContext(github.context)

  // eslint-disable-next-line prefer-const
  let ignoreIfAssigned = false

  // Refresh for latest changes
  // eslint-disable-next-line prefer-const
  let issue = await getIssue(issueContext)

  if (ignoreIfAssigned && issueHasBeenAssigned(issue)) {
    return 'No action being taken. Ignoring because one or more assignees have been added to the issue'
  }

  const mentionedCves = findMentionedCves(issue)

  if (mentionedCves.length === 0) {
    return 'Did not find any CVEs mentioned'
  }

  await addLabels(issueContext, mentionedCves.map(formatLabelName))

  const recs = await getTideliftRecommendations(mentionedCves)

  if (recs.length === 0) {
    return `Did not find any Tidelift recommendations for CVEs: ${mentionedCves}`
  }

  for (const rec of recs) {
    await createRecommendationCommentIfNeeded(issueContext, rec)
  }

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
