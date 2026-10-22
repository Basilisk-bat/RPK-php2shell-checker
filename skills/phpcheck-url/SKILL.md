---
name: phpcheck-url
description: Check the advertised PHP version from a URL or hostname.
---

From this skill's directory, run:

```sh
node scripts/phpcheck.js "https://example.com" --json
```

Use HTTPS for a bare hostname. The checker reads `Server` and `X-Powered-By`
headers. If the version is hidden, report unknown.

Versions below an upstream fix return `potentially_vulnerable` with exit code 1.
PHP 5.4–5.6, 7.0–7.4, 8.0 and 8.1 also return this warning. A higher patch
number on those branches, such as 8.1.35, does not establish a fix.

Exit code 1 is a version-based warning, not proof that the installed package
is unpatched. HTTP headers cannot tell whether the version contains a
backported fix. Describe the result as potentially vulnerable, never confirmed
vulnerable.

An `ok` result with exit code 0 means only that the advertised stable version
meets an upstream fixed release: 8.2.35, 8.3.36, 8.4.27 or 8.5.12. The installed
build is not verified. Missing or unrecognized versions, prereleases and failed
checks return `unknown` with exit code 3.

Headers can be changed. A server-side check of the package serving the site
is stronger evidence. Do not run exploit probes.

Exit codes 1 and 3 are check results. Invalid arguments exit with code 2.
