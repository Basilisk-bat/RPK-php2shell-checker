---
name: phpcheck-safe
description: Check a website or local PHP version for the October 2026 PHP vulnerability without exploit requests.
---

From this skill's directory, run the bundled checker with the user's URL:

```sh
node phpcheck.js "https://example.com" --json
```

Only check local PHP when the user asks for it:

```sh
node phpcheck.js --local --json
```

Report the verdict and PHP version. Exit codes 1 and 3 mean `vulnerable` and `unknown`, not execution failures. `unknown` does not mean patched. Do not add exploit probes.
