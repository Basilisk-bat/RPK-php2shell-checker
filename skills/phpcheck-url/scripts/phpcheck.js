#!/usr/bin/env node
const { parseArgs } = require('node:util')

const VERSION = '1.0.0'
// Official PHP releases fixing both CVEs, published 2026-10-21.
const FIXED_IN = { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 }
const OLDER_BRANCHES = new Set(['5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1'])
const USAGE = 'Usage: node phpcheck.js URL [--timeout SECONDS] [--json]\n' +
  '       node phpcheck.js --version'

function versionStatus(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)([-+~].*)?$/.exec(version || '')
  if (!match) return 'unknown'
  if (/(?:^|[-+~.])(?:dev|alpha|beta|rc)/i.test(match[4] || '')) return 'unknown'
  const branch = `${Number(match[1])}.${Number(match[2])}`
  if (OLDER_BRANCHES.has(branch)) return 'potentially_vulnerable'
  const fixed = FIXED_IN[branch]
  if (fixed === undefined) return 'unknown'
  if (Number(match[3]) < fixed) return 'potentially_vulnerable'
  return 'ok'
}

async function urlHeaders(address, timeout) {
  if (/[\x00-\x20\x7f]/.test(address)) throw new Error('URL contains spaces or control characters')
  const url = new URL(address)
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use an http:// or https:// URL')
  if (url.username || url.password || url.hash) throw new Error('URL credentials and fragments are not supported')
  const headers = []
  for (const method of ['HEAD', 'GET']) {
    const response = await fetch(url, {
      method, redirect: 'manual', signal: AbortSignal.timeout(Math.ceil(timeout * 1000)),
    })
    headers.push(response.headers.get('server') || '', response.headers.get('x-powered-by') || '')
    await response.body?.cancel()
    if (![405, 501].includes(response.status)) break
  }
  return headers.join('\n')
}

async function main() {
  let values, address, timeout
  try {
    const args = parseArgs({
      allowPositionals: true,
      options: {
        timeout: { type: 'string', default: '10' },
        json: { type: 'boolean' },
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
  } catch (error) {
    console.error(error.message + '\n' + USAGE)
    process.exitCode = 2
    return
  }

  let version = null, error = null, status = 'unknown'
  try {
    const text = await urlHeaders(address, timeout)
    for (const match of text.matchAll(/\bPHP[ /]([^\s,;)]+)/gi)) {
      const candidateStatus = versionStatus(match[1])
      // Prefer warnings and unrecognized versions over a reassuring banner.
      if (version === null || candidateStatus === 'potentially_vulnerable' || status === 'ok') {
        version = match[1]
        status = candidateStatus
      }
      if (status === 'potentially_vulnerable') break
    }
  } catch (exc) {
    error = exc.message
  }

  let result = { patch_status: 'unknown', reason: error || 'PHP version not found' }
  if (version && !error) {
    result = {
      patch_status: status,
      reason: status === 'ok'
        ? `PHP ${version}: advertised version meets an upstream fixed release. Installed build not verified.`
        : `PHP ${version}: ${status === 'potentially_vulnerable' ? 'Potentially vulnerable. ' : ''}` +
          'HTTP headers cannot tell whether this version contains a backported fix.',
    }
  }
  const code = { ok: 0, potentially_vulnerable: 1, unknown: 3 }[result.patch_status]
  const report = { ...result, php_version: version, exit_code: code }
  console.log(values.json ? JSON.stringify(report) : result.patch_status.replace('_', ' ').toUpperCase() + ': ' + result.reason)
  process.exitCode = code
}

main()
