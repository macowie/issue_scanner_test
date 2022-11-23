import {VulnerabilityId} from './vulnerability'
import {error, info} from '@actions/core'
import {fetchUrl, is404} from './utils'
export class TideliftRecommendation {
  vuln_id: VulnerabilityId
  description: string
  severity: number
  recommendation_created_at: Date
  recommendation_updated_at: Date
  impact_score: number
  impact_description: string
  other_conditions: boolean
  other_conditions_description?: string
  workaround_available: boolean
  workaround_description?: string
  specific_methods_affected: boolean
  specific_methods_description?: string
  real_issue: boolean
  false_positive_reason?: string

  constructor(vuln_id: VulnerabilityId, recommendationData: {}) {
    this.vuln_id = vuln_id
    this.description = recommendationData['description']
    this.severity = recommendationData['severity']
    this.recommendation_created_at =
      recommendationData['recommendation_created_at']
    this.recommendation_updated_at =
      recommendationData['recommendation_updated_at']
    this.impact_score = recommendationData['impact_score']
    this.impact_description = recommendationData['impact_description']
    this.other_conditions = recommendationData['other_conditions']
    this.other_conditions_description =
      recommendationData['other_conditions_description']
    this.workaround_available = recommendationData['workaround_available']
    this.workaround_description = recommendationData['workaround_description']
    this.specific_methods_affected =
      recommendationData['specific_methods_affected']
    this.specific_methods_description =
      recommendationData['specific_methods_description']
    this.real_issue = recommendationData['real_issue']
    this.false_positive_reason = recommendationData['false_positive_reason']
  }
}

export async function fetchTideliftRecommendation(
  vuln_id: VulnerabilityId,
  tideliftToken: string
): Promise<TideliftRecommendation | undefined> {
  const config = {
    headers: {
      Authorization: `Bearer ${tideliftToken}`
    }
  }

  try {
    const response = await fetchUrl(
      `https://api.tidelift.com/external-api/v1/vulnerability/${vuln_id}/recommendation`,
      config
    )
    return new TideliftRecommendation(vuln_id, response.data)
  } catch (err) {
    if (is404(err)) {
      info(`Did not find Tidelift recommendation for: ${vuln_id}`)
      return
    }
    error(`Problem fetching Tidelift recommendation for: ${vuln_id}`)
  }
}

export async function fetchTideliftRecommendations(
  vuln_ids: VulnerabilityId[],
  tideliftToken: string
): Promise<TideliftRecommendation[]> {
  const recs = await Promise.all(
    vuln_ids.map(async vuln_id =>
      fetchTideliftRecommendation(vuln_id, tideliftToken)
    )
  )

  return recs.filter(
    r => r instanceof TideliftRecommendation
  ) as TideliftRecommendation[]
}
