import {expect, describe, test} from '@jest/globals'
import {findMentionedVulnerabilities, scanGhsa, scanCve} from '../src/scanner'
import {GithubClient} from '../src/github_client'
import {Configuration} from '../src/configuration'

const github = new GithubClient(Configuration.defaults().github_token)

describe('findMentionedVulnerabilities', () => {
  test('searches CVE ids, normalizes them', async () => {
    const input = ['CVE-5555-1234', 'cvE-2022-2222']
    const expected = ['CVE-5555-1234', 'CVE-2022-2222']
    const subject = await findMentionedVulnerabilities(input)

    expect(subject.toString()).toEqual(expected.toString())
  })

  test('results are unique', async () => {
    const input = ['cvE-2022-2222  cvE-2022-2222', 'cvE-2022-2222 lorem']
    const subject = await findMentionedVulnerabilities(input)

    expect(subject.length).toBe(1)
  })

  test('finds cve from github advisory', async () => {
    const input = ['baz GHSA-vv3r-fxqp-vr3f foo']
    const expected = ['CVE-2022-38147']
    const subject = await findMentionedVulnerabilities(input, github)

    expect(subject.toString()).toEqual(expected.toString())
  })

  test('results are unique across indirectly found cves', async () => {
    const input = ['CVE-2022-38147', 'GHSA-vv3r-fxqp-vr3f']
    const subject = await findMentionedVulnerabilities(input, github)

    expect(subject.length).toBe(1)
  })
})

describe('scanGhsa', () => {
  test('finds ghsa ids in text', async () => {
    expect(scanGhsa('baz GHSA-vv3r-fxqp-vr3f foo')).toEqual([
      'GHSA-vv3r-fxqp-vr3f'
    ])
  })
})

describe('scanCve', () => {
  test('extracts formatted', async () => {
    expect(scanCve('baz CVE-5555-1234 cvE-2022-2222 foo')).toEqual([
      'CVE-5555-1234',
      'CVE-2022-2222'
    ])
  })
})
