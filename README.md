# PHP Check

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

[Apache 2.0 license](LICENSE).
