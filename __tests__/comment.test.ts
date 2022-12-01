import {expect, test} from '@jest/globals'
import {formatRecommendationText} from '../src/comment'
import {
  TideliftRecommendation
} from '../src/tidelift_recommendation'
import { VulnerabilityId } from '../src/vulnerability'

const vuln_id = new VulnerabilityId('cve-2021-3807')
const rec = new TideliftRecommendation(vuln_id, {
  false_positive_reason: "asdf",
  impact_description: "jkl;",
  workaround_description: "qwerty"
})

describe('formatRecommendationText', () => {
  test('includes recommendation descriptions', async () => {
    expect(formatRecommendationText(rec)).toMatch("asdf")
    expect(formatRecommendationText(rec)).toMatch("jkl;")
    expect(formatRecommendationText(rec)).toMatch("qwerty")
  })
})
