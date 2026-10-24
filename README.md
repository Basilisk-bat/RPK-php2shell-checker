# PHP Version Checker

Get a version-based PHP2Shell warning from a website's PHP headers. The server
skill explains how to check the actual serving package when you have access.

To install both skills, ask Codex:

```text
$skill-installer install both skills from https://github.com/Basilisk-bat/RPK-php2shell-checker
```

Use [phpcheck-server](skills/phpcheck-server/SKILL.md) when you have server
access, or [phpcheck-url](skills/phpcheck-url/SKILL.md) when you only have a URL:

```text
$phpcheck-url check https://example.com
```

```text
$phpcheck-server check the PHP version serving my site
```

## Run directly

Check a website:

```sh
node phpcheck.js "https://example.com"
```

For an owned site or a target you are authorized to test, compare its `HEAD`
and `GET` responses at the same URL:

```sh
node phpcheck.js "https://example.com" --compare-methods --json
```

Each opt-in invocation sends a fresh `HEAD` and `GET` request to the supplied
URL, even when `HEAD` succeeds; it does not retry automatically. The
`--timeout` limit applies separately to each method. The JSON
`evidence` lists each method, HTTP status, and numeric PHP versions found in
`Server` or `X-Powered-By`; it flags conflicting versions and incomplete
comparisons. It does not include the target URL, full header values, or response
bodies. Build suffixes are omitted from evidence. Both methods must return a
successful response with the same fixed PHP version for `OK`. A conflict or
failed request prevents `OK` unless another banner already warrants a
`POTENTIALLY VULNERABLE` warning. These are header observations, not proof of
the serving build or exploitability.

## Results

| Result | Exit code | Meaning |
| --- | --- | --- |
| `OK` | `0` | Advertised version meets an upstream fixed release; serving build is unverified. |
| `POTENTIALLY VULNERABLE` | `1` | Advertised upstream version is below a fix or on an older branch; serving build is unverified. |
| `UNKNOWN` | `3` | Missing or unrecognized version, prerelease, or failed check. |

Use `--json` for machine-readable output. `patch_status` is `ok`,
`potentially_vulnerable` or `unknown`; it is a version-based URL check, not a
deployed-build verdict.
`serving_patch_status` is always `unknown`: headers cannot establish whether the
running worker has a vendor backport, or even whether it matches the banner.
Invalid arguments exit with code `2`.

Versions below a listed upstream fix return `potentially_vulnerable` and
exit `1`. PHP 5.4–5.6, 7.0–7.4, 8.0 and 8.1 also return this warning, even
with a higher patch number such as 8.1.35.

## URL checks

Ordinary URL mode reads `X-Powered-By` and `Server` from a `HEAD` response. It
does not send `GET`, follow redirects, or inspect response bodies. If `HEAD`
returns 405 or 501, the result is `UNKNOWN`, even when that response advertises
a PHP version. An authorized `--compare-methods --json` check explicitly sends
both methods. Missing or hidden PHP headers also return `UNKNOWN`.

The upstream fixed releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12, from the
[October 21 PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5).
HTTP headers cannot tell whether the version contains a backported fix. Even `OK`
only describes the advertised version - it doesn't verify the installation!
For example, an `8.1.2-1ubuntu2.28` banner still produces a version warning,
although [Ubuntu's advisory](https://ubuntu.com/security/notices/USN-8948-1)
lists that package revision as fixed for Ubuntu 22.04. The installed package
and actual serving worker must be checked before applying that verdict.
See [phpcheck-server](skills/phpcheck-server/SKILL.md) for that check. A header
cannot authenticate the package revision or prove which build serves the URL.
The checker does not send exploit probes.

## Contributing

This is an RPK fork of [OpenAI's php2shell-checker](https://github.com/openai/php2shell-checker).
See [CONTRIBUTING.md](CONTRIBUTING.md) for this fork's contribution guidance.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
