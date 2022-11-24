import {expect, test} from '@jest/globals'
import {getInput} from '@actions/core'
import * as dotenv from 'dotenv'
import {VulnerabilityId} from '../src/vulnerability'
import {
  fetchTideliftRecommendation,
  fetchTideliftRecommendations,
  TideliftRecommendation
} from '../src/tidelift_recommendation'
dotenv.config()

const tideliftToken =
  getInput('tidelift-token') || process.env.TIDELIFT_TOKEN || 'NO_TOKEN'

const fakeVuln = new VulnerabilityId('CVE-5555-1234')
const realVuln = new VulnerabilityId('cve-2021-3807')

test('fetchTideliftRecommendation', async () => {
  expect(await fetchTideliftRecommendation(fakeVuln, tideliftToken)).toBe(
    undefined
  )

  expect(
    await fetchTideliftRecommendation(realVuln, tideliftToken)
  ).toBeInstanceOf(TideliftRecommendation)
})

test('fetchTideliftRecommendations', async () => {
  const vulns = [realVuln, fakeVuln]
  expect(await fetchTideliftRecommendations(vulns, tideliftToken)).toHaveLength(
    1
  )
})
