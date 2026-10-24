---
name: phpcheck-url
description: Check the advertised PHP version from a URL or hostname.
---

Use only on a site you own or are explicitly authorized to check. Ordinary
mode sends a `HEAD` request; opt-in comparison also sends `GET`.

From this skill's directory, run:

```sh
node scripts/phpcheck.js "https://example.com" --json
```

Ordinary URL checks send only `HEAD`. A non-2xx response (including a redirect
or error page) returns `unknown` without sending `GET` or classifying its PHP
banner. HTTP 405 and 501 retain a specific "HEAD request was not supported"
reason.
Both URL modes report only bounded numeric PHP versions. Server-controlled
build suffixes and malformed version tokens are omitted from JSON and text.

On that authorized site, use `--compare-methods --json` to send `HEAD` and
`GET` to the same URL and inspect each response's status and
PHP version tokens. The comparison does not follow redirects or read bodies.
It reports only selected header names and numeric PHP versions, not the URL
or full headers. Both methods need successful responses advertising the same
fixed PHP version for `ok`. Non-2xx statuses and sanitized PHP banners remain
in the evidence with candidate `patch_status: unknown`; only 2xx banners can
determine a version-based verdict.
Treat conflicting banners or an incomplete comparison as unknown unless a
2xx banner already warrants a `potentially_vulnerable` warning.

Use HTTPS for a bare hostname. The checker reads `Server` and `X-Powered-By`
headers. If the version is hidden, report unknown.

Versions below an upstream fix return `potentially_vulnerable` with exit code 1.
PHP 5.4–5.6, 7.0–7.4, 8.0 and 8.1 also return this warning. A higher patch
number on those branches, such as 8.1.35, does not establish a fix.
The warning also applies to prerelease banners below a listed fix or on an
older branch. A prerelease at or above a fixed patch remains `unknown`.

Exit code 1 is a version-based warning, not proof that the installed package
is unpatched. HTTP headers cannot tell whether the version contains a
backported fix. Describe the result as potentially vulnerable, never confirmed
vulnerable.

In JSON, `patch_status` is a version-based URL check and
`serving_patch_status` remains `unknown` for every URL result. A vendor-looking
suffix in a header does not authenticate the package or identify the serving
worker. Check the actual serving package and vendor advisory before reporting
deployment patch status.

An `ok` result with exit code 0 means only that the advertised stable version
meets an upstream fixed release: 8.2.35, 8.3.36, 8.4.27 or 8.5.12. The installed
build is not verified. Missing or unrecognized versions, prereleases at or above
the fixed patch, and failed checks return `unknown` with exit code 3.

Headers can be changed. A server-side check of the package serving the site
is stronger evidence. Do not run exploit probes.

Exit codes 1 and 3 are check results. Invalid arguments exit with code 2.
