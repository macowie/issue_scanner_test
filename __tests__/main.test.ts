import {expect, test} from '@jest/globals'
import {findMentionedVulnerabilities, VulnerabilityId} from '../src/main'

test('findMentionedVulnerabilities', async () => {
  const input = {title: 'CVE-555-1234 ', body: 'cvE-2022-2222'}
  expect(findMentionedVulnerabilities(input)).toEqual([
    new VulnerabilityId('CVE-555-1234'),
    new VulnerabilityId('CVE-2022-2222')
  ])
})
