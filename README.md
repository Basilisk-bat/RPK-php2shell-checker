# PHP Version Checker

Check a website or local PHP binary to see if it's vulnerable to php2shell.

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

Check the local CLI PHP

```sh
node phpcheck.js --local
```

## Results

| Result | Exit code | Meaning |
| --- | --- | --- |
| `OK` | `0` | Stable PHP patch version above the embedded cutoff for a listed major/minor branch. |
| `VULNERABLE` | `1` | PHP version at or below the embedded cutoff for that branch. |
| `UNKNOWN` | `3` | No PHP version or response, an unrecognized version/branch, or a newer prerelease build. |

Use `--json` for machine-readable output (`patch_status` is `ok`, `vulnerable`,
or `unknown`). Invalid arguments exit with code `2`.

## Tests

```sh
node --test phpcheck.test.js
```

Tests run the CLI against local HTTP servers and a fake PHP executable.
No PHP installation or external website is required.

## Limitations

The checker only evaluates versions exposed in HTTP response headers or by
`php -v`. It reads `X-Powered-By` and `Server`, sends `HEAD`, and falls back to
`GET` only when `HEAD` returns 405 or 501. It does not follow redirects or
inspect response bodies. Missing or hidden PHP headers return `UNKNOWN`.

`OK` is a version comparison based on the assumption that subsequent stable patches in each listed branch contain the fix.
It does not independently verify a security fix. Check the versions against
the official PHP security release. Headers can be hidden or changed, and distribution backports may
not change the upstream version. `UNKNOWN` does not mean the target is patched!

## Contributing

OpenAI is not accepting external code contributions to this project. Bug
reports and non-code feedback are welcome through GitHub issues. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the [Apache License 2.0](LICENSE).
