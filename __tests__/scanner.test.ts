import {expect, describe, test} from '@jest/globals'
import {
  findMentionedVulnerabilities,
  scanGhsa,
  scanCve,
  Scanner
} from '../src/scanner'
import {GithubClient} from '../src/github_client'
import {Configuration} from '../src/configuration'
import {Issue} from '../src/issue'

const readOnlyGithub = new GithubClient(Configuration.defaults().github_token)
readOnlyGithub.addComment = jest.fn()
readOnlyGithub.addLabels = jest.fn()

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
    const subject = await findMentionedVulnerabilities(input, readOnlyGithub)

    expect(subject.toString()).toEqual(expected.toString())
  })

  test('results are unique across indirectly found cves', async () => {
    const input = ['CVE-2022-38147', 'GHSA-vv3r-fxqp-vr3f']
    const subject = await findMentionedVulnerabilities(input, readOnlyGithub)

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

describe('Scanner', () => {
  test('has config', () => {
    let subject = new Scanner()
    expect(subject.config).toEqual(Configuration.defaults())
  })

  test('fake issue', async () => {
    let issue = new Issue({repo: 'foo', owner: 'bar', issue_number: 1})
    let subject = await new Scanner({}).perform(issue)

    expect(subject).toContain(Scanner.statuses.no_issue_data(''))
  })

  test('perform no vulns mentioned', async () => {
    let issue = new Issue({repo: 'codeql', owner: 'github', issue_number: 1})
    let subject = await new Scanner({github: readOnlyGithub}).perform(issue)

    expect(subject).toContain(Scanner.statuses.no_vulnerabilities())
  })

  test('perform success', async () => {
    let issue = new Issue({repo: 'codeql', owner: 'github', issue_number: 8707})
    let subject = await new Scanner({github: readOnlyGithub}).perform(issue)

    expect(subject).toContain('CVE-2021-43297')
  })
})
