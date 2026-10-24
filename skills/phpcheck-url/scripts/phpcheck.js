#!/usr/bin/env node
const { parseArgs } = require('node:util')

const VERSION = '1.0.0'
// Official PHP releases fixing both CVEs, published 2026-10-21.
const FIXED_IN = { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 }
const OLDER_BRANCHES = new Set(['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1'])
const PHP_BANNER = /(\[)?\bPHP(?:\/|[ \t]+)([^\s,;)]+)/gi
const USAGE = 'Usage: node phpcheck.js URL [--timeout SECONDS] [--json] [--compare-methods]\n' +
  '       node phpcheck.js --version\n' +
  'Check only an owned or explicitly authorized target; ordinary mode sends HEAD, comparison adds GET.'

function versionStatus(version) {
  // Keep the ordinary URL verdict within the same bounded version grammar used
  // for comparison evidence. Unbounded digits can become Infinity in Number().
  const numericVersion = safeVersion(version)
  if (!numericVersion) return 'unknown'
  const [major, minor, patch] = numericVersion.split('.').map(Number)
  const branch = `${major}.${minor}`
  if (OLDER_BRANCHES.has(branch)) return 'potentially_vulnerable'
  const fixed = FIXED_IN[branch]
  if (fixed === undefined) return 'unknown'
  if (patch < fixed) return 'potentially_vulnerable'
  // A prerelease of the fixed patch might not contain the final fix.
  const suffix = version.slice(numericVersion.length)
  if (/(?:^|[-+~.])(?:dev|alpha|beta|rc)\d*(?=$|[-+~.])/i.test(suffix)) return 'unknown'
  return 'ok'
}

function checkedUrl(address) {
  if (/[\x00-\x20\x7f]/.test(address)) throw new Error('URL contains spaces or control characters')
  const url = new URL(address)
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use an http:// or https:// URL')
  if (url.username || url.password || url.hash) throw new Error('URL credentials and fragments are not supported')
  return url
}

function isSuccessfulStatus(status) {
  return status >= 200 && status < 300
}

async function urlHeaders(address, timeout) {
  const url = checkedUrl(address)
  const response = await fetch(url, {
    method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(Math.ceil(timeout * 1000)),
  })
  await response.body?.cancel()
  if ([405, 501].includes(response.status)) {
    throw new Error(`HEAD request was not supported (HTTP ${response.status}); no GET request was sent`)
  }
  if (!isSuccessfulStatus(response.status)) {
    throw new Error(`HEAD request did not return a successful response (HTTP ${response.status}); no GET request was sent`)
  }
  return [response.headers.get('server') || '', response.headers.get('x-powered-by') || ''].join('\n')
}

// Report only numeric versions. A server controls header values, including
// build suffixes, so the evidence mode must not echo those suffixes.
function safeVersion(token) {
  const match = /^((?:0|[1-9]\d{0,3})\.(?:0|[1-9]\d{0,3})\.(?:0|[1-9]\d{0,3}))(?:[-+~][A-Za-z0-9.+~_-]{1,64}|(?:dev|alpha|beta|rc)\d{0,4})?$/i.exec(token)
  return match ? match[1] : null
}

function bannerToken(match) {
  // Strip a closing bracket only when this banner opened with one.
  return match[1] && match[2].endsWith(']') ? match[2].slice(0, -1) : match[2]
}

function headerCandidates(response) {
  const candidates = []
  for (const header of ['server', 'x-powered-by']) {
    for (const match of (response.headers.get(header) || '').matchAll(PHP_BANNER)) {
      const token = bannerToken(match)
      const phpVersion = safeVersion(token)
      candidates.push({
        header, php_version: phpVersion,
        patch_status: phpVersion && isSuccessfulStatus(response.status) ? versionStatus(token) : 'unknown',
      })
    }
  }
  return candidates
}

async function compareMethods(address, timeout) {
  const url = checkedUrl(address)
  const observations = []
  for (const method of ['HEAD', 'GET']) {
    try {
      const response = await fetch(url, {
        method, redirect: 'manual', signal: AbortSignal.timeout(Math.ceil(timeout * 1000)),
      })
      const candidates = headerCandidates(response)
      await response.body?.cancel()
      observations.push({ method, http_status: response.status, candidates })
    } catch (error) {
      observations.push({ method, error: error?.name === 'TimeoutError' ? 'timeout' : 'request_failed' })
    }
  }

  const candidates = observations.flatMap(observation => observation.candidates || [])
  // Non-2xx banners remain visible as evidence, but cannot determine the
  // top-level version verdict for the requested URL.
  const verdictCandidates = observations
    .filter(observation => isSuccessfulStatus(observation.http_status))
    .flatMap(observation => observation.candidates || [])
  const versions = [...new Set(candidates.map(candidate => candidate.php_version).filter(Boolean))]
  const conflictingVersions = versions.length > 1
  const comparisonComplete = observations.every(observation => !observation.error)
  const warning = verdictCandidates.find(candidate => candidate.patch_status === 'potentially_vulnerable')
  const unknown = verdictCandidates.some(candidate => candidate.patch_status === 'unknown')
  const bothMethodsHave2xxCandidates = observations.every(observation =>
    isSuccessfulStatus(observation.http_status) && observation.candidates?.length)
  const non2xxBanner = observations.some(observation =>
    !isSuccessfulStatus(observation.http_status) && observation.candidates?.length)
  const evidenceSufficientForOk = Boolean(bothMethodsHave2xxCandidates && !warning && !unknown && !conflictingVersions)
  let patchStatus = 'unknown', phpVersion = null, reason = 'PHP version not found in either response'
  if (warning) {
    patchStatus = 'potentially_vulnerable'
    phpVersion = warning.php_version
    reason = 'An advertised PHP version is below an upstream fix or on an older branch. Vendor backports and the serving build are unverified.'
  } else if (evidenceSufficientForOk) {
    patchStatus = 'ok'
    phpVersion = versions[0]
    reason = 'Both responses advertise an upstream fixed PHP version. The installed and serving builds are unverified.'
  } else if (conflictingVersions) {
    reason = 'Responses advertise different PHP versions; identify the serving build before deciding patch status.'
  } else if (!comparisonComplete) {
    reason = 'The method comparison was incomplete; identify the serving build before deciding patch status.'
  } else if (unknown) {
    reason = 'A PHP banner could not be classified; identify the serving build before deciding patch status.'
  } else if (!bothMethodsHave2xxCandidates) {
    reason = 'Both methods did not provide a successful response with a PHP banner; identify the serving build before deciding patch status.'
  }
  if (conflictingVersions && warning) reason += ' Responses also advertise different PHP versions.'
  if (patchStatus === 'unknown' && non2xxBanner) reason += ' PHP banners on non-2xx responses are evidence only.'
  const exitCode = { ok: 0, potentially_vulnerable: 1, unknown: 3 }[patchStatus]
  return {
    patch_status: patchStatus, serving_patch_status: 'unknown',
    reason, php_version: phpVersion, exit_code: exitCode,
    evidence: {
      mode: 'compare_methods', observed_at: new Date().toISOString(),
      comparison_complete: comparisonComplete, evidence_sufficient_for_ok: evidenceSufficientForOk,
      conflicting_versions: conflictingVersions,
      observations,
    },
  }
}

async function main() {
  let values, address, timeout
  try {
    const args = parseArgs({
      allowPositionals: true,
      options: {
        timeout: { type: 'string', default: '10' },
        json: { type: 'boolean' },
        'compare-methods': { type: 'boolean' },
        version: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
    })
    values = args.values
    if (values.version) return console.log(VERSION)
    if (values.help) return console.log(USAGE)
    address = args.positionals[0]
    if (args.positionals.length !== 1) {
      throw new Error('Provide one URL')
    }
    timeout = Number(values.timeout)
    if (!(timeout > 0 && timeout <= 60)) throw new Error('--timeout must be greater than 0 and at most 60 seconds')
    if (values['compare-methods'] && !values.json) throw new Error('--compare-methods requires --json')
  } catch (error) {
    console.error(error.message + '\n' + USAGE)
    process.exitCode = 2
    return
  }

  if (values['compare-methods']) {
    try {
      const report = await compareMethods(address, timeout)
      console.log(JSON.stringify(report))
      process.exitCode = report.exit_code
    } catch (error) {
      console.log(JSON.stringify({
        patch_status: 'unknown', serving_patch_status: 'unknown',
        reason: error.message, php_version: null, exit_code: 3,
      }))
      process.exitCode = 3
    }
    return
  }

  let version = null, seenCandidate = false, error = null, status = 'unknown'
  try {
    const text = await urlHeaders(address, timeout)
    for (const match of text.matchAll(PHP_BANNER)) {
      const token = bannerToken(match)
      const candidateStatus = versionStatus(token)
      // Emit the same bounded numeric evidence as comparison mode. Header
      // suffixes are target-controlled and can contain private identifiers.
      const candidateVersion = safeVersion(token)
      // Prefer warnings and unrecognized versions over a reassuring banner.
      if (!seenCandidate || candidateStatus === 'potentially_vulnerable' || status === 'ok') {
        version = candidateVersion
        status = candidateStatus
        seenCandidate = true
      }
      if (status === 'potentially_vulnerable') break
    }
  } catch (exc) {
    error = exc.message
  }

  let result = { patch_status: 'unknown', reason: error || 'PHP version not found' }
  if (seenCandidate && !version && !error) {
    result = { patch_status: 'unknown', reason: 'PHP banner could not be classified.' }
  } else if (version && !error) {
    result = {
      patch_status: status,
      reason: status === 'ok'
        ? `PHP ${version}: advertised version meets an upstream fixed release. Installed build not verified.`
        : `PHP ${version}: ${status === 'potentially_vulnerable' ? 'Potentially vulnerable. ' : ''}` +
          'HTTP headers cannot tell whether this version contains a backported fix.',
    }
  }
  const code = { ok: 0, potentially_vulnerable: 1, unknown: 3 }[result.patch_status]
  const report = { ...result, serving_patch_status: 'unknown', php_version: version, exit_code: code }
  console.log(values.json ? JSON.stringify(report) : result.patch_status.replace('_', ' ').toUpperCase() + ': ' + result.reason)
  process.exitCode = code
}

main()
