import {VulnerabilityId} from './main'
import {getInput, error} from '@actions/core'
import {Axios, AxiosError} from 'axios'

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

export async function getTideliftRecommendation(
  vuln_id: VulnerabilityId
): Promise<TideliftRecommendation | undefined> {
  const config = {
    headers: {
      Authorization: `Bearer ${tideliftToken}`
    }
  }
  try {
    const response = await new Axios(config).get(
      `https://api.tidelift.com/external-api/v1/vulnerability/${vuln_id}/recommendation`
    )

    return new TideliftRecommendation(vuln_id, response.data)
  } catch (err) {
    if (err instanceof AxiosError && err.response?.status === 404) {
      // Not Found
    }

    error(`Problem fetching Tidelift Recommendations for: ${vuln_id}`)
  }
}

export async function getTideliftRecommendations(
  vuln_ids: VulnerabilityId[]
): Promise<TideliftRecommendation[]> {
  const recs = await Promise.all(vuln_ids.map(getTideliftRecommendation))
  return recs.filter(
    r => r instanceof TideliftRecommendation
  ) as TideliftRecommendation[]
}

const tideliftToken = getInput('tidelift-token')
