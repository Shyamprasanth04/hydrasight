# Development

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,docs]"
```

## Quality gates

All gates run in CI (Python 3.10 / 3.11 / 3.12):

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy (strict function contracts)
make test        # pytest -p no:ethereum
make coverage    # pytest with branch coverage (floor 75%)
make docs        # mkdocs build --strict
make build       # python -m build (sdist + wheel)
```

Or directly:

```bash
ruff check hydrasight/ tests/
ruff format --check hydrasight/ tests/
mypy hydrasight/ --ignore-missing-imports
pylint hydrasight/ --fail-under=9.0
pytest tests/ -p no:ethereum -q
pytest tests/ -p no:ethereum --cov=hydrasight --cov-branch --cov-fail-under=75
mkdocs build --strict
python -m build
```

## Project conventions

- **Public API**: REPL commands and config keys stay backward-compatible.
- **Type safety**: all functions are annotated; `mypy` enforces
  `disallow_untyped_defs`, `check_untyped_defs`, `strict_equality`, and more.
  Generic `dict` parameterization warnings (`[type-arg]`) are intentionally not
  chased.
- **Exceptions**: catch specific exception types at network/IO boundaries;
  reserve broad catches for genuine last-resort boundaries (REPL loop,
  per-finding verifier isolation, PDF build) and mark them `# noqa: BLE001`.
- **Tests**: keep the suite green; add coverage for new modules (75.75% branch
  measured; CI floors at 75%).

## Release

See `RELEASING.md`. Merged PRs are tagged `vX.Y.Z`; the `release.yml`
workflow builds, twine-checks, publishes to PyPI via trusted publishing
(OIDC), and publishes a GitHub Release.
