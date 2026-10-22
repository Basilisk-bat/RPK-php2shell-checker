# PHP Version Checker

Get a version-based PHP2Shell warning from a website's PHP headers or local installation.

To install both skills, ask Codex:

```text
$skill-installer install both skills from https://github.com/openai/php2shell-checker
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

## Results

| Result | Exit code | Meaning |
| --- | --- | --- |
| `OK` | `0` | Advertised version meets an upstream fixed release. |
| `POTENTIALLY VULNERABLE` | `1` | Advertised version is in an affected range. |
| `UNKNOWN` | `3` | Missing or unrecognized version, prerelease, or failed check. |

Use `--json` for machine-readable output. `patch_status` is `ok`,
`potentially_vulnerable` or `unknown`. Invalid arguments exit with code `2`.

Versions below a listed upstream fix return `potentially_vulnerable` and
exit `1`. PHP 5.4–5.6, 7.0–7.4, 8.0 and 8.1 also return this warning, even
with a higher patch number such as 8.1.35.

## URL checks

URL mode reads `X-Powered-By` and `Server`, sends `HEAD`, and falls back to
`GET` only when `HEAD` returns 405 or 501. It does not follow redirects or
inspect response bodies. Missing or hidden PHP headers return `UNKNOWN`.

The upstream fixed releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12, from the
[October 21 PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5).
HTTP headers cannot tell whether the version contains a backported fix. Even `OK`
only describes the advertised version - it doesn't verify the installation!
The checker does not send exploit probes.

## Contributing

OpenAI is not accepting external code contributions to this project. Bug
reports and non-code feedback are welcome through GitHub issues. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the [Apache License 2.0](LICENSE).
