import {getInput} from '@actions/core'
import {TideliftRecommendation} from './tidelift_recommendation'
import * as dotenv from 'dotenv'
import {possibleIssueNumber} from './issue'
dotenv.config()

type TemplateSet = {
  vuln_label: (vuln_id: string) => string
  recommendation_body: (rec: TideliftRecommendation) => string
  has_recommendation_label: () => string
}

export class Configuration {
  issue_number: possibleIssueNumber
  tidelift_token?: string
  github_token: string
  ignore_if_assigned: boolean
  templates: TemplateSet

  constructor(options: Partial<Configuration> = {}) {
    const defaults = Configuration.defaults()

    this.issue_number = options['issue_number'] || defaults['issue_number']
    this.github_token = options['github_token'] || defaults['github_token']
    this.tidelift_token =
      options['tidelift_token'] || defaults['tidelift_token']
    this.ignore_if_assigned =
      options['ignore_if_assigned'] || defaults['ignore_if_assigned']
    this.templates = options['templates'] || defaults['templates']
  }

  static defaults(): Configuration {
    const github_token = getInput('repo-token') || process.env.GITHUB_TOKEN
    if (!github_token) {
      throw new Error('Could not initialize github client from env')
    }

    return {
      issue_number: getInput('issue-number'),
      ignore_if_assigned: isTruthy(getInput('ignore-if-assigned')),
      tidelift_token: getInput('tidelift-token') || process.env.TIDELIFT_TOKEN,
      github_token,
      templates: {
        vuln_label: formatVulnerabilityLabel,
        recommendation_body: formatRecommendationBody,
        has_recommendation_label: formatHasRecommenationLabel
      }
    }
  }
}

function formatVulnerabilityLabel(vuln_id: string): string {
  return `:yellow_circle: ${vuln_id}`
}

function formatHasRecommenationLabel(): string {
  return `:green_circle: has-recommendation`
}

function formatRecommendationBody(
  recommendation: TideliftRecommendation
): string {
  return `:wave: It looks like you are talking about ${recommendation.vulnerability}. I have more information to help you handle this CVE.

Is this a legit issue with this project? ${recommendation.real_issue}
${recommendation.false_positive_reason}

How likely are you impacted (out of 10)? ${recommendation.impact_score}
${recommendation.impact_description}

Is there a workaround available? ${recommendation.workaround_available}
${recommendation.workaround_description}`
}

function isTruthy(val): boolean {
  return ['true', 't', 'yes'].includes(String(val).toLowerCase())
}
