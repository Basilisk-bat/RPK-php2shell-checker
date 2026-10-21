# PHP Security Version Checker

Check a website or local PHP version without exploit requests. Uses Node.js. No packages to install.

To install, ask Codex:

```text
$skill-installer install the phpcheck-safe skill from https://github.com/openai/phrenetic-pheasant-checker
```

Then ask:

```text
$phpcheck-safe check https://example.com
```

## Run directly

Check a website:

```sh
node phpcheck.js "https://example.com"
```

Check local PHP:

```sh
node phpcheck.js --local
```

## Limitations

The checker only evaluates versions exposed in HTTP response headers or by
`php -v`. `UNKNOWN` means it could not confirm a vulnerable version, not that
the target is patched. The embedded version ranges are current as of October
20, 2026.

## Contributing

OpenAI is not accepting external code contributions to this project. Bug
reports and non-code feedback are welcome through GitHub issues. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the [Apache License 2.0](LICENSE).
