import { VulnerabilityId } from "./main"
import { getInput } from "@actions/core"
import axios from 'axios'

const tideliftToken = getInput("tidelift-token")

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

  constructor(vuln_id: VulnerabilityId, recommendationData: Object) {
    this.vuln_id = vuln_id
    this.description = recommendationData["description"]
    this.severity = recommendationData["severity"]
    this.recommendation_created_at = recommendationData["recommendation_created_at"]
    this.recommendation_updated_at = recommendationData["recommendation_updated_at"]
    this.impact_score = recommendationData["impact_score"]
    this.impact_description = recommendationData["impact_description"]
    this.other_conditions = recommendationData["other_conditions"]
    this.other_conditions_description = recommendationData["other_conditions_description"]
    this.workaround_available = recommendationData["workaround_available"]
    this.workaround_description = recommendationData["workaround_description"]
    this.specific_methods_affected = recommendationData["specific_methods_affected"]
    this.specific_methods_description = recommendationData["specific_methods_description"]
    this.real_issue = recommendationData["real_issue"]
    this.false_positive_reason = recommendationData["false_positive_reason"]   
  }
}

export async function getTideliftRecommendation(vuln_id: VulnerabilityId): Promise<TideliftRecommendation> {

  let config = {
    headers: {
      'Authorization': `Bearer ${tideliftToken}`
    }
  }

  return axios.get(`https://api.tidelift.com/external-api/v1/vulnerability/${vuln_id}/recommendation`, config).
    then(response => response.data).
    catch(err => {
      if (err.response && err.response.status === 404) {
        return null
      }

      console.error(`Problem fetching Tidelift Recommendations for: ${vuln_id}`)
    }).
    then(data => new TideliftRecommendation(vuln_id, data))
}


export async function getTideliftRecommendations(vuln_ids: VulnerabilityId[]): Promise<TideliftRecommendation[]> {
  let recs = await Promise.all(vuln_ids.map(vuln_id => getTideliftRecommendation(vuln_id)))
  return recs.filter(r => r)
}