import {TideliftRecommendation} from './tidelift_recommendation'
import {Issue} from './issue'

function formatRecommendationText(
  recommendation: TideliftRecommendation
): string {
  return `:wave: Looks like you're reporting ${
    recommendation.vuln_id
  }.\n\n${JSON.stringify(recommendation)}`
}

export async function createRecommendationCommentIfNeeded(
  issue: Issue,
  rec: TideliftRecommendation
): Promise<object | undefined> {
  const comments = await issue.fetchComments()
  if (!comments) {
    return
  }

  const botComments = comments.filter(comment => {
    return (
      isBotReportComment(comment) &&
      commentIncludesText(comment, rec.vuln_id.id)
    )
  })

  if (botComments.length === 0)
    return issue.addComment(formatRecommendationText(rec))
}

function isBotReportComment(comment): boolean {
  return comment.user?.login === 'github-actions[bot]'
}

function commentIncludesText(comment, query: string): boolean {
  return comment.body?.includes(query)
}
