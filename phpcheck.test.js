const assert = require('node:assert/strict')
const { spawn } = require('node:child_process')
const { once } = require('node:events')
const { cp, mkdtemp, rm } = require('node:fs/promises')
const http = require('node:http')
const { tmpdir } = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

function run(args, script = path.join(__dirname, 'phpcheck.js')) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args])
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject)
    child.on('close', code => resolve({ code, stdout, stderr }))
  })
}

async function serve(t, handler) {
  const server = http.createServer(handler)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise(resolve => {
    server.close(resolve)
    server.closeAllConnections()
  }))
  return `http://127.0.0.1:${server.address().port}/`
}

function check(result, status, version) {
  const code = { ok: 0, potentially_vulnerable: 1, unknown: 3 }[status]
  assert.equal(result.stderr, '')
  assert.equal(result.code, code, result.stdout)
  const report = JSON.parse(result.stdout)
  assert.equal(report.patch_status, status)
  assert.equal(report.serving_patch_status, 'unknown')
  assert.equal(report.php_version, version)
  assert.equal(report.exit_code, code)
  return report
}

for (const header of ['X-Powered-By', 'x-PoWeReD-bY', 'Server']) {
  for (const [version, status] of [['8.4.26', 'potentially_vulnerable'], ['8.4.27', 'ok'], ['8.4.100', 'ok']]) {
    test(`${header}: PHP/${version} => ${status}`, async t => {
      const methods = []
      const url = await serve(t, (req, res) => {
        methods.push(req.method)
        res.setHeader(header, header === 'Server' ? `Apache/2.4.62 (Unix) PHP/${version}` : `PHP/${version}`)
        res.end()
      })
      check(await run([url, '--json']), status, version)
      assert.deepEqual(methods, ['HEAD'])
    })
  }
}

test('URL checks warn below each upstream fix and accept the fixed version', async t => {
  // Explicit fixtures: these assert the CLI contract without importing its classifier.
  const boundaries = ['8.2.34', '8.3.35', '8.4.26', '8.5.11']
  let header
  const url = await serve(t, (req, res) => { res.setHeader('X-Powered-By', header); res.end() })
  for (const version of boundaries) {
    header = `PHP/${version}`
    const report = check(await run([url, '--json']), 'potentially_vulnerable', version)
    assert.match(report.reason, /Potentially vulnerable/)
    assert.match(report.reason, /HTTP headers cannot tell whether this version contains a backported fix/)
    const [major, minor, patch] = version.split('.').map(Number)
    const newer = `${major}.${minor}.${patch + 1}`
    header = `PHP/${newer}`
    check(await run([url, '--json']), 'ok', newer)
  }
})

for (const version of ['5.4.45', '5.5.38', '5.6.40', '7.0.33', '7.1.33', '7.2.34', '7.3.33', '7.4.33', '8.0.30', '8.1.34', '8.1.35', '8.1.99']) {
  test(`older branch PHP/${version} => potentially vulnerable regardless of patch number`, async t => {
    const url = await serve(t, (req, res) => {
      res.setHeader('X-Powered-By', `PHP/${version}`)
      res.end()
    })
    const report = check(await run([url, '--json']), 'potentially_vulnerable', version)
    assert.match(report.reason, /HTTP headers cannot tell whether this version contains a backported fix/)
  })
}

for (const version of ['8.6.0', '9.0.0', '8.4', 'not-a-version', '8.4.27RC1', '8.4.27-rc1', '8.4.27~beta1']) {
  test(`unrecognized or prerelease PHP/${version} => unknown`, async t => {
    const url = await serve(t, (req, res) => { res.setHeader('X-Powered-By', `PHP/${version}`); res.end() })
    check(await run([url, '--json']), 'unknown', version)
  })
}

for (const version of ['8.4.26-dev', '8.2.30RC1', '7.4.33-dev', '8.1.35RC1', '8.1.35-dev']) {
  test(`below-fix or older-branch prerelease PHP/${version} warns in both URL modes`, async t => {
    const url = await serve(t, (req, res) => { res.setHeader('X-Powered-By', `PHP/${version}`); res.end() })
    const ordinary = check(await run([url, '--json']), 'potentially_vulnerable', version)
    assert.match(ordinary.reason, /backported fix/)
    const compared = check(await run([url, '--compare-methods', '--json']), 'potentially_vulnerable', version.replace(/(?:[-+~]?(?:dev|alpha|beta|rc)\d*)$/i, ''))
    assert.equal(compared.evidence.observations[0].candidates[0].patch_status, 'potentially_vulnerable')
    assert.equal(compared.evidence.evidence_sufficient_for_ok, false)
  })
}

for (const [version, status] of [['8.4.26-1ubuntu1', 'potentially_vulnerable'], ['8.1.2-1ubuntu2.28', 'potentially_vulnerable'], ['8.4.27-1ubuntu1', 'ok'], ['8.4.27-1.devuan1', 'ok']]) {
  test(`distribution suffix PHP/${version} => ${status}`, async t => {
    const url = await serve(t, (req, res) => { res.setHeader('X-Powered-By', `PHP/${version}`); res.end() })
    const report = check(await run([url, '--json']), status, version)
    if (version === '8.1.2-1ubuntu2.28') {
      // This package revision is a known Ubuntu fix, but a header cannot bind it to the serving worker.
      assert.match(report.reason, /backported fix/)
      assert.equal(report.serving_patch_status, 'unknown')
    }
    if (version === '8.4.27-1.devuan1') {
      const compared = check(await run([url, '--compare-methods', '--json']), 'ok', '8.4.27')
      assert.equal(compared.evidence.evidence_sufficient_for_ok, true)
    }
  })
}

test('no PHP headers => unknown, even if the body mentions a PHP version', async t => {
  const url = await serve(t, (req, res) => {
    res.setHeader('Server', 'nginx')
    res.setHeader('X-Powered-By', 'Express')
    res.end('PHP/8.4.27')
  })
  const report = check(await run([url, '--json']), 'unknown', null)
  assert.equal(report.reason, 'PHP version not found')
  const text = await run([url])
  assert.equal(text.code, 3)
  assert.equal(text.stdout, 'UNKNOWN: PHP version not found\n')
})

test('empty HTTP response headers => unknown', async t => {
  const url = await serve(t, (req, res) => { res.sendDate = false; res.end() })
  check(await run([url, '--json']), 'unknown', null)
})

test('connection closes without any HTTP response => unknown', async t => {
  const url = await serve(t, req => { req.socket.destroy() })
  const report = check(await run([url, '--json']), 'unknown', null)
  assert.ok(report.reason)
})

test('a response timeout => unknown', async t => {
  const url = await serve(t, () => {})
  const report = check(await run([url, '--timeout', '0.1', '--json']), 'unknown', null)
  assert.match(report.reason, /timeout/i)
})

for (const statusCode of [405, 501]) {
  test(`HEAD ${statusCode} stays unknown without an implicit GET`, async t => {
    const methods = []
    const url = await serve(t, (req, res) => {
      methods.push(req.method)
      if (req.method === 'HEAD') res.statusCode = statusCode
      res.setHeader('X-Powered-By', 'PHP/8.4.27')
      res.end()
    })
    const ordinary = check(await run([url, '--json']), 'unknown', null)
    assert.equal(ordinary.reason, `HEAD request was not supported (HTTP ${statusCode}); no GET request was sent`)
    assert.deepEqual(methods, ['HEAD'])

    methods.length = 0
    const comparison = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
    assert.deepEqual(methods, ['HEAD', 'GET'])
    assert.deepEqual(comparison.evidence.observations.map(o => o.http_status), [statusCode, 200])
    assert.equal(comparison.evidence.evidence_sufficient_for_ok, false)
  })
}

for (const [statusCode, version] of [[302, '8.4.27'], [304, '8.4.26'], [404, '8.4.27'], [503, '8.4.26']]) {
  test(`HEAD ${statusCode} ignores PHP/${version} and stays unknown without GET`, async t => {
    const methods = []
    const url = await serve(t, (req, res) => {
      methods.push(req.method)
      res.statusCode = statusCode
      if (statusCode === 302) res.setHeader('Location', 'http://127.0.0.1:1/')
      res.setHeader('X-Powered-By', `PHP/${version}`)
      res.end()
    })
    const result = check(await run([url, '--json']), 'unknown', null)
    assert.equal(result.reason, `HEAD request did not return a successful response (HTTP ${statusCode}); no GET request was sent`)
    assert.deepEqual(methods, ['HEAD'])
  })
}

test('a successful 204 HEAD can still classify a PHP banner', async t => {
  const methods = []
  const url = await serve(t, (req, res) => {
    methods.push(req.method)
    res.statusCode = 204
    res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.end()
  })
  check(await run([url, '--json']), 'ok', '8.4.27')
  assert.deepEqual(methods, ['HEAD'])
})

for (const [server, poweredBy, expectedVersion, status] of [
  ['8.4.26', '8.4.27', '8.4.26', 'potentially_vulnerable'],
  ['8.4.27', '8.4.26', '8.4.26', 'potentially_vulnerable'],
  ['8.1.35', '8.4.27', '8.1.35', 'potentially_vulnerable'],
  ['8.4.27', '8.1.35', '8.1.35', 'potentially_vulnerable'],
  ['9.0.0', '8.4.27', '9.0.0', 'unknown'],
  ['8.4.27', '9.0.0', '9.0.0', 'unknown'],
]) {
  test(`conflicting headers ${server} / ${poweredBy} => ${status}`, async t => {
    const url = await serve(t, (req, res) => {
      res.setHeader('Server', `Apache/2.4.62 PHP/${server}`)
      res.setHeader('X-Powered-By', `PHP/${poweredBy}`)
      res.end()
    })
    check(await run([url, '--json']), status, expectedVersion)
  })
}

test('plain text warning has exit code 1 and the backport caveat', async t => {
  const url = await serve(t, (req, res) => {
    res.setHeader('X-Powered-By', 'PHP/8.4.26')
    res.end()
  })
  const result = await run([url])
  assert.equal(result.stderr, '')
  assert.equal(result.code, 1)
  assert.equal(result.stdout, 'POTENTIALLY VULNERABLE: PHP 8.4.26: Potentially vulnerable. HTTP headers cannot tell whether this version contains a backported fix.\n')
})

test('plain text output for a newer version is OK with exit code 0', async t => {
  const url = await serve(t, (req, res) => { res.setHeader('X-Powered-By', 'PHP/8.4.27'); res.end() })
  const result = await run([url])
  assert.equal(result.stderr, '')
  assert.equal(result.code, 0)
  assert.equal(result.stdout, 'OK: PHP 8.4.27: advertised version meets an upstream fixed release. Installed build not verified.\n')
})

test('the URL skill runs independently with its bundled checker', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'phpcheck-url-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await cp(path.join(__dirname, 'skills/phpcheck-url'), directory, { recursive: true })
  const methods = []
  let headStatus = 200
  const url = await serve(t, (req, res) => {
    methods.push(req.method)
    if (req.method === 'HEAD') res.statusCode = headStatus
    res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.end()
  })
  const script = path.join(directory, 'scripts/phpcheck.js')
  const result = await run([url, '--json'], script)
  check(result, 'ok', '8.4.27')
  assert.deepEqual(methods, ['HEAD'])

  methods.length = 0
  headStatus = 405
  check(await run([url, '--json'], script), 'unknown', null)
  assert.deepEqual(methods, ['HEAD'])

  methods.length = 0
  headStatus = 302
  check(await run([url, '--json'], script), 'unknown', null)
  assert.deepEqual(methods, ['HEAD'])
})

test('opt-in method comparison reports both observations without response bodies', async t => {
  const methods = []
  const url = await serve(t, (req, res) => {
    methods.push(req.method)
    res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.end('private body text')
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'ok', '8.4.27')
  assert.deepEqual(methods, ['HEAD', 'GET'])
  assert.equal(result.evidence.mode, 'compare_methods')
  assert.equal(result.evidence.comparison_complete, true)
  assert.equal(result.evidence.evidence_sufficient_for_ok, true)
  assert.equal(result.evidence.conflicting_versions, false)
  assert.ok(Number.isFinite(Date.parse(result.evidence.observed_at)))
  assert.deepEqual(result.evidence.observations.map(({ method, http_status, candidates }) => ({ method, http_status, candidates })), [
    { method: 'HEAD', http_status: 200, candidates: [{ header: 'x-powered-by', php_version: '8.4.27', patch_status: 'ok' }] },
    { method: 'GET', http_status: 200, candidates: [{ header: 'x-powered-by', php_version: '8.4.27', patch_status: 'ok' }] },
  ])
  assert.doesNotMatch(JSON.stringify(result), /private body text/)
  assert.doesNotMatch(JSON.stringify(result), /127\.0\.0\.1/)
})

test('method mismatch keeps the warning and makes the conflict visible', async t => {
  const url = await serve(t, (req, res) => {
    res.setHeader('Server', `PHP/${req.method === 'HEAD' ? '8.4.27' : '8.4.26'}`)
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'potentially_vulnerable', '8.4.26')
  assert.equal(result.evidence.conflicting_versions, true)
  assert.equal(result.evidence.evidence_sufficient_for_ok, false)
  assert.match(result.reason, /different PHP versions/)
})

test('conflicting fixed banners are unknown rather than a reassuring OK', async t => {
  const url = await serve(t, (req, res) => {
    res.setHeader('Server', `PHP/${req.method === 'HEAD' ? '8.4.27' : '8.5.12'}`)
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.equal(result.evidence.conflicting_versions, true)
  assert.equal(result.evidence.evidence_sufficient_for_ok, false)
})

test('a failed HEAD still permits GET evidence but cannot produce OK', async t => {
  const url = await serve(t, (req, res) => {
    if (req.method === 'HEAD') return req.socket.destroy()
    res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.equal(result.evidence.comparison_complete, false)
  assert.equal(result.evidence.observations[0].error, 'request_failed')
  assert.equal(result.evidence.observations[1].http_status, 200)
})

test('a fixed banner on GET alone does not establish an OK comparison', async t => {
  const url = await serve(t, (req, res) => {
    if (req.method === 'GET') res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.equal(result.evidence.comparison_complete, true)
  assert.equal(result.evidence.evidence_sufficient_for_ok, false)
})

test('redirect banners do not establish an OK comparison', async t => {
  const url = await serve(t, (req, res) => {
    res.statusCode = 302
    res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.setHeader('Location', 'http://127.0.0.1:1/')
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.equal(result.evidence.evidence_sufficient_for_ok, false)
  assert.deepEqual(result.evidence.observations.map(o => o.http_status), [302, 302])
})

test('comparison does not follow redirects or echo arbitrary header tokens', async t => {
  const methods = []
  const url = await serve(t, (req, res) => {
    methods.push(req.method)
    res.statusCode = 302
    res.setHeader('Location', 'http://127.0.0.1:1/should-not-be-requested')
    res.setHeader('X-Powered-By', 'PHP/8.4.27@private-token')
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.deepEqual(methods, ['HEAD', 'GET'])
  assert.deepEqual(result.evidence.observations.map(o => o.http_status), [302, 302])
  assert.equal(result.evidence.observations[0].candidates[0].php_version, null)
  assert.equal(result.evidence.evidence_sufficient_for_ok, false)
  assert.doesNotMatch(JSON.stringify(result), /private-token|should-not-be-requested/)
})

test('comparison strips target-controlled package suffixes from evidence', async t => {
  const url = await serve(t, (req, res) => {
    res.setHeader('X-Powered-By', 'PHP/8.4.27+private_token')
    res.end()
  })
  const result = check(await run([url, '--compare-methods', '--json']), 'ok', '8.4.27')
  assert.doesNotMatch(JSON.stringify(result), /private_token/)
  assert.equal(result.evidence.observations[0].candidates[0].php_version, '8.4.27')
})

for (const version of ['8.4.27-rc1', '8.4.27RC1']) {
  test(`comparison keeps fixed-patch prerelease PHP/${version} unknown after stripping its suffix`, async t => {
    const url = await serve(t, (req, res) => {
      res.setHeader('X-Powered-By', `PHP/${version}`)
      res.end()
    })
    const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
    assert.equal(result.evidence.observations[0].candidates[0].php_version, '8.4.27')
    assert.equal(result.evidence.observations[0].candidates[0].patch_status, 'unknown')
    assert.equal(result.evidence.evidence_sufficient_for_ok, false)
    assert.match(result.reason, /could not be classified/)
  })
}

test('oversized numeric banners cannot become OK or enter the report', async t => {
  const patch = '9'.repeat(3000)
  let header = `PHP/8.4.${patch}`
  let alsoAdvertiseFixed = false
  const methods = []
  const url = await serve(t, (req, res) => {
    methods.push(req.method)
    res.setHeader('Server', header)
    if (alsoAdvertiseFixed) res.setHeader('X-Powered-By', 'PHP/8.4.27')
    res.end()
  })
  const ordinary = check(await run([url, '--json']), 'unknown', null)
  assert.equal(ordinary.reason, 'PHP banner could not be classified.')
  assert.doesNotMatch(JSON.stringify(ordinary), /9{100}/)
  assert.deepEqual(methods, ['HEAD'])

  const result = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.equal(result.evidence.observations[0].candidates[0].php_version, null)
  assert.equal(result.evidence.evidence_sufficient_for_ok, false)
  assert.doesNotMatch(JSON.stringify(result), /9{100}/)

  alsoAdvertiseFixed = true
  const mixed = check(await run([url, '--json']), 'unknown', null)
  assert.doesNotMatch(JSON.stringify(mixed), /9{100}/)

  header = 'PHP/8.4.27'
  alsoAdvertiseFixed = false
  methods.length = 0
  check(await run([url, '--json']), 'ok', '8.4.27')
  assert.deepEqual(methods, ['HEAD'])
})

test('zero-padded PHP banners cannot produce an OK result', async t => {
  const url = await serve(t, (req, res) => {
    res.setHeader('X-Powered-By', 'PHP/0008.0004.0027')
    res.end()
  })
  const comparison = check(await run([url, '--compare-methods', '--json']), 'unknown', null)
  assert.equal(comparison.evidence.comparison_complete, true)
  assert.equal(comparison.evidence.evidence_sufficient_for_ok, false)
  assert.deepEqual(comparison.evidence.observations.map(o => o.candidates[0]), [
    { header: 'x-powered-by', php_version: null, patch_status: 'unknown' },
    { header: 'x-powered-by', php_version: null, patch_status: 'unknown' },
  ])
  check(await run([url, '--json']), 'unknown', '0008.0004.0027')
})

test('comparison requires JSON before sending requests', async t => {
  const methods = []
  const url = await serve(t, (req, res) => { methods.push(req.method); res.end() })
  const result = await run([url, '--compare-methods'])
  assert.equal(result.code, 2)
  assert.match(result.stderr, /--compare-methods requires --json/)
  assert.deepEqual(methods, [])
})

test('comparison rejects a non-HTTP URL without implying a serving patch verdict', async () => {
  const report = check(await run(['file:///not-a-target', '--compare-methods', '--json']), 'unknown', null)
  assert.match(report.reason, /http:\/\/ or https:\/\//)
})
