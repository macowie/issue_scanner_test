import {TideliftRecommendation} from './tidelift_recommendation'
import {Issue} from './issue'
import {commentData, GithubClient} from './github_client'

export async function createRecommendationCommentIfNeeded(
  issue: Issue,
  rec: TideliftRecommendation,
  github: GithubClient,
  template: Function
): Promise<{} | undefined> {
  const comments = await github.listComments(issue)

  if (!comments) {
    return
  }

  const botComments = comments.filter(comment => {
    return (
      isBotReportComment(comment) &&
      commentIncludesText(comment, rec.vulnerability.id)
    )
  })

  if (botComments.length === 0)
    return github.addComment(issue, template.call(rec))
}

function isBotReportComment(comment: commentData): boolean {
  return comment.user?.login === 'github-actions[bot]'
}

function commentIncludesText(comment: commentData, query: string): boolean {
  return !!comment.body?.includes(query)
}
