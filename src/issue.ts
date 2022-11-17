import {getInput} from '@actions/core'
import {context as githubContext} from '@actions/github'

export type IssueNumber = number
export type RepoOwner = string
export type RepoName = string
export type IssueContext = {
  owner: RepoOwner
  repo: RepoName
  issue_number: IssueNumber
}

export class IssueNotFoundError extends Error {}

export function getCurrentIssue(octokit): Issue {
  return new Issue(getIssueContext(githubContext), octokit)
}

export class Issue {
  owner: RepoOwner
  repo: RepoName
  issue_number: IssueNumber
  octokit
  data?

  constructor(context: IssueContext, octokit) {
    this.owner = context.owner
    this.repo = context.repo
    this.issue_number = context.issue_number
    this.octokit = octokit
  }

  get context(): IssueContext {
    return {owner: this.owner, repo: this.repo, issue_number: this.issue_number}
  }

  get hasAssignees(): boolean {
    return !!this.data?.assignees && this.data.assignees.length > 0
  }

  async addComment(body: string): Promise<{} | undefined> {
    return this.octokit.rest.issues.createComment({
      ...this.context,
      body
    })
  }

  async fetchComments(): Promise<{}[] | undefined> {
    const {data} = await this.octokit.rest.issues.listComments(this.context)
    return data
  }

  async refreshData(): Promise<{} | undefined> {
    const {data} = await this.octokit.rest.issues.get(this.context)
    this.data = data
    return this.data
  }

  async addLabels(labels: string[]): Promise<{} | undefined> {
    return this.octokit.rest.issues.addLabels({...this.context, labels})
  }
}

function getIssueContext(context): IssueContext {
  const repo = context.payload?.repository?.name
  const owner = context.payload?.repository?.owner?.login
  const issue_number = getIssueNumber(context)

  if (repo && owner && issue_number) return {repo, owner, issue_number}

  throw new IssueNotFoundError()
}

function getIssueNumber(context): IssueNumber {
  const possibleNumber =
    getInput('issue-number') ||
    context.payload?.issue?.number ||
    context.payload?.pull_request?.number

  if (possibleNumber) return Number(possibleNumber)

  throw new IssueNotFoundError()
}
