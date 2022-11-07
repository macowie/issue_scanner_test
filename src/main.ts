import * as core from '@actions/core'
import * as github from '@actions/github'
import { Context } from "@actions/github/lib/context"

import { TideliftRecommendation, getTideliftRecommendations } from "./tidelift_recommendation"

const myToken = core.getInput("repo-token");
const octokit = github.getOctokit(myToken);

export type VulnerabilityId = string
export type IssueNumber = number
export type RepoOwner = string
export type RepoName = string

async function getIssue(repoOwner: RepoOwner, repoName: RepoName, issueNumber: IssueNumber) {
  return octokit.rest.issues.get({
    owner: repoOwner,
    repo: repoName,
    issue_number: issueNumber
  });
}

async function addLabels(repoOwner: RepoOwner, repoName: RepoName, issueNumber: IssueNumber, labels: string[]) {
  return octokit.rest.issues.addLabels({
    owner: repoOwner,
    repo: repoName,
    issue_number: issueNumber,
    labels: labels
  });
}

async function addComment(repoOwner: RepoOwner, repoName: RepoName, issueNumber: IssueNumber, body: string) {
  return octokit.rest.issues.createComment({
    owner: repoOwner,
    repo: repoName,
    issue_number: issueNumber,
    body: body
  });
}

function issueHasBeenAssigned(issue): boolean {
  return issue.data.assignees.length !== 0
}

function getIssueNumber(core, context: Context): IssueNumber {
  let issueNumber = core.getInput("issue-number");

  // return what is provided
  if (issueNumber) return issueNumber;

  // return the one found in issue
  issueNumber = context.payload.issue && context.payload.issue.number;
  if (issueNumber) return issueNumber;

  // return the one found in PR
  issueNumber =
    context.payload.pull_request && context.payload.pull_request.number;
  if (issueNumber) return issueNumber;

  let card_url =
    context.payload.project_card && context.payload.project_card.content_url;
  issueNumber = card_url && card_url.split("/").pop();

  return issueNumber;
}

function findMentionedCves(issue): VulnerabilityId[] {
  const regex = /CVE-[\d]+-[\d]+/ig
  const searchFields = ["body", "title"]

  return Array.from(new Set(searchFields.
    map(field => issue.data[field]).
    filter(field => typeof(field) === 'string').
    flatMap(field => field.match(regex)).
    filter(field => field)
  ))
}

function formatLabelName(cve: VulnerabilityId): string {
  return`:yellow_circle: ${cve.toUpperCase()}`
}

function formatRecommendationText(recommendation: TideliftRecommendation): string {
  return`:wave: Looks like you're reporting ${recommendation.vuln_id}.\n\n${JSON.stringify(recommendation)}`
}

function formatRecommendationsComment(recs: TideliftRecommendation[]): string {
  return recs.map(formatRecommendationText).join("\n\n")
}

async function scanIssue() {
  const repoName = github.context?.payload?.repository?.name as RepoName
  const repoOwner = github.context?.payload?.repository?.owner?.login as RepoOwner
  var ignoreIfAssigned = false

  let issueNumber = getIssueNumber(core, github.context)

  if (issueNumber === undefined) {
    return "No action being taken. Ignoring because issueNumber was not identified";
  }

  // Refresh for latest changes
  var issue = await getIssue(repoOwner, repoName, issueNumber)

  if (ignoreIfAssigned && issueHasBeenAssigned(issue)) {
    return "No action being taken. Ignoring because one or more assignees have been added to the issue";
  }

  let mentionedCves = findMentionedCves(issue)

  console.log("CVES found:", mentionedCves)

  if (mentionedCves.length == 0) {
    return "Did not find any CVEs mentioned";
  }

  await addLabels(repoOwner, repoName, issueNumber, mentionedCves.map(formatLabelName))

  let recs = await getTideliftRecommendations(mentionedCves)

  if (recs.length == 0) {
    return `Did not find any Tidelift recommendations for CVEs: ${mentionedCves}`;
  }

  await addComment(repoOwner, repoName, issueNumber, formatRecommendationsComment(recs))
  
  return `Found: ${mentionedCves}; Recs: ${recs}`
}


async function run(): Promise<void> {
  try {
    scanIssue().
      then(result => {
        console.log(result)
      }).catch(err => {
        core.setFailed(err)
      })
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
  }
}

run()
