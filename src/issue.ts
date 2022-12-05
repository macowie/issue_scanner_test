import {GithubClient, issueData} from './github_client'
import {notBlank} from './utils'

export type issueNumber = number
export type repoOwner = string
export type repoName = string
export type issueContext = {
  owner: repoOwner
  repo: repoName
  issue_number: issueNumber
}

export class IssueNotFoundError extends Error {}
export class Issue {
  owner: repoOwner
  repo: repoName
  issue_number: issueNumber
  data?: issueData | undefined

  constructor(context: issueContext) {
    this.owner = context.owner
    this.repo = context.repo
    this.issue_number = context.issue_number
  }

  get context(): issueContext {
    return {owner: this.owner, repo: this.repo, issue_number: this.issue_number}
  }

  get hasAssignees(): boolean {
    return !!this.data?.assignees && this.data.assignees.length > 0
  }

  get searchableText(): string[] {
    const searchableFields = ['title', 'body']

    return searchableFields
      .map(field => this.data && this.data[field])
      .filter(notBlank)
  }

  async fetchData(github: GithubClient): Promise<issueData> {
    this.data = await github.getIssue(this.context)

    return this.data
  }
}

export function findCurrentIssue(githubContext, issue_number): Issue {
  return new Issue(findIssueContext(githubContext, issue_number))
}

function findIssueContext(context, issue_number): issueContext {
  const repo = context.payload?.repository?.name
  const owner = context.payload?.repository?.owner?.login
  issue_number = findIssueNumber(context, issue_number)

  if (repo && owner && issue_number) return {repo, owner, issue_number}

  throw new IssueNotFoundError()
}

function findIssueNumber(context, issue_number): issueNumber {
  const possibleNumber =
    issue_number ||
    context.payload?.issue?.number ||
    context.payload?.pull_request?.number

  if (possibleNumber) return Number(possibleNumber)

  throw new IssueNotFoundError()
}
