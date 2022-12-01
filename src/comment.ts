import {TideliftRecommendation} from './tidelift_recommendation'
import {Issue} from './issue'

export function formatRecommendationText(
  recommendation: TideliftRecommendation
): string {
  return `:wave: It looks like you are talking about ${recommendation.vuln_id}. I have more information to help you handle this CVE.

Is this a legit issue with this project? ${recommendation.real_issue}
${recommendation.false_positive_reason}

How likely are you impacted (out of 10)? ${recommendation.impact_score}
${recommendation.impact_description}

Is there a workaround available? ${recommendation.workaround_available}
${recommendation.workaround_description}`
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
