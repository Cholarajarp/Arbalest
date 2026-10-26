# Contributing to Arbalest

Contributions from beginners and experienced developers are welcome. Bug reports,
documentation fixes, regression tests, parser improvements, and code reviews all
help. For a substantial change, open an issue first to discuss scope and avoid
duplicating work.

## Report bugs and security issues

For ordinary bugs, include your operating system, Python/Node version, Arbalest
version or commit, steps to reproduce, expected behavior, and actual behavior.
Use a small synthetic repository where possible. Remove credentials, private
source, and personal information from logs and reports.

For suspected vulnerabilities in Arbalest, follow [SECURITY.md](SECURITY.md).
Do not disclose them in public issues or pull requests. Only scan repositories
and systems you own or are explicitly authorized to assess.

## Development setup

Use Python **3.12+**; CI tests Python 3.12 on Windows and Linux. The optional
TypeScript SDK requires **Node.js 22+**. Run the following from the repository
root after cloning your fork:

```sh
python -m pip install uv==0.11.21
uv sync --locked --group dev
uv run arbalest --help
```

The lockfile is the reproducible development environment. For an intentional
Python dependency change, update `pyproject.toml`, the corresponding
`requirements.txt` or `requirements-dev.txt`, and regenerate `uv.lock` with
`uv lock`. Avoid unrelated dependency upgrades.

### Credentials and live services

Most development and the default test suite do not require provider credentials,
Docker, or a hosted sandbox. Tests isolate provider configuration and skip local
`.env` loading.

For an explicit live smoke test, copy `.env.example` to your private `.env`,
select a supported provider, and supply your own credentials. Configure the
verification sandbox separately. Do not commit `.env`, keys, private reports,
or checkpoint data. Never add credentials to project JSON or SDK arguments.

Live model calls, advisory lookups, intelligence searches, and hosted sandbox
runs can involve network access, data sharing, and charges to your own accounts.
Use synthetic or non-sensitive fixtures. Run `arbalest sandbox-check` before
executing generated code; generated code must not run directly on the host.

## Python checks

Start with the tests relevant to your change, then run the checks used by CI:

```sh
uv run pytest tests/test_scan_pipeline.py -q
uv run ruff check .
uv run mypy
uv run pytest -q
uv run bandit -q -ll -r engine arbalest_cli.py mcp_server.py
uv run pip-audit -r requirements.txt
uv build
```

The dependency audit needs network access. Report failures honestly, including
any checks you could not run. Do not remove meaningful code or disable security
checks just to make validation pass.

To exercise the local synthetic taint corpus without executing fixture code:

```sh
uv run python benchmarks/taint/runner.py
```

These fixture results are regression evidence, not independent benchmark results
or proof that the scanner cannot miss vulnerabilities.

## TypeScript SDK checks

From `sdk/typescript`:

```sh
npm ci --no-audit --no-fund
npm test
npm pack --dry-run
```

`npm test` compiles the SDK and runs its tests. Commit `package-lock.json` when
changing SDK dependencies. Do not commit `node_modules` or generated `dist`
output. See [the SDK guide](docs/sdk.md) for usage and error contracts.

## Source distributions

`MANIFEST.in` controls extra files included in Python source distributions, such
as this guide, security guidance, documentation, templates, and examples. Keep
it when changing packaging; these files are not all selected by Python package
discovery. Inclusion in a source distribution does not automatically install
these documents as runtime resources in a wheel. Never include private `.env`
files or local runtime artifacts.

## Pull requests

- Keep changes focused and follow existing code patterns.
- Add regression tests for behavior changes and fixes; update affected docs.
- Preserve fail-closed behavior: incomplete scans must not become clean verdicts.
- Record unsupported inputs, omitted coverage, and budget exhaustion explicitly.
- Keep model and sandbox configuration independent and credentials environment-based.
- Treat source, model output, and generated code as untrusted inputs.
- Explain the change, validation performed, and remaining limitations in the PR.
- Use a short, imperative commit subject, ideally no more than 50 characters.

See [project workflows](docs/project-workflows.md) and
[architecture](docs/architecture.md) for implementation context. For release
changes, also run `uv run python scripts/verify-release.py --check-files` and
follow [the release guide](docs/releases.md). Publishing is a maintainer action,
not part of ordinary contribution testing.

## License

By submitting a contribution, you agree to license it under the project's
[MIT License](LICENSE). Only contribute material you have the right to share,
and preserve applicable copyright notices and third-party license obligations.
