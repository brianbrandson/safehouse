# Contributing to Safehouse

Safehouse is a small local-first CLI. Keep changes narrow, safety-first, and free of real client data, credentials, paths, or engagement artifacts.

## Verify a change

Use Python 3.11+ and [uv](https://docs.astral.sh/uv/):

```bash
uv sync
uv run scripts/check
```

`scripts/check` is the public-source contributor gate. It compiles the source, runs the unit tests, and exercises a disposable fake-VeraCrypt smoke flow. It does not create real VeraCrypt containers, mount volumes, or read your normal Safehouse config.

Use it after changing source, tests, or operator documentation. Normal installed users do not need to run it.

## Keep the patch reviewable

- Add or update tests for behavior changes.
- Preserve dry-run-first and no-force behavior for destructive actions.
- Keep passwords, tokens, client material, and real host paths out of source, tests, issues, and pull requests.
- Do not add dependencies unless the standard library is genuinely insufficient.
