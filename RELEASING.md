# Releasing HydraSight

Releases are fully automatic once a tag lands on GitHub. No API tokens, no
manual uploads.

## Checklist

1. **Gate check** — `main` must be green: ruff, pylint (≥ 9.0), mypy,
   `pytest --cov-branch --cov-fail-under=75`, `mkdocs build --strict`.
   ```bash
   pip install -e ".[dev,docs]"
   ruff check hydrasight/ tests/ && ruff format --check hydrasight/ tests/
   pylint hydrasight/ --fail-under=9.0
   mypy hydrasight/ --ignore-missing-imports
   pytest tests/ -p no:ethereum --cov=hydrasight --cov-branch --cov-fail-under=75
   mkdocs build --strict
   ```
2. **Bump the version** in `hydrasight/constants.py` (`__version__ = "X.Y.Z"`).
   The package, `pyproject.toml`, and the CI banner all read this one line.
3. **Update the changelog** — `CHANGELOG.md` (canonical) and `docs/changelog.md`.
4. Open a PR, merge to `main` (CI runs again and must pass).
5. **Tag and push** from the merged `main` tip:
   ```bash
   git tag -a vX.Y.Z -m "HydraSight X.Y.Z — <CODENAME>"
   git push origin vX.Y.Z
   ```

## What happens on `git push` of a `v*` tag

`.github/workflows/release.yml`:

1. `build` — `python -m build` (sdist + wheel) and `twine check`.
2. `publish-pypi` — publishes to PyPI via **OIDC trusted publishing**.
3. `github-release` — creates the GitHub Release with both dist files and
   generated notes.

## One-time PyPI setup (trusted publishing)

If a new version ever fails `publish-pypi` with `invalid-publisher`, re-check
the pending/live publisher at <https://pypi.org/manage/account/publishing/>:

- Owner: `Shyamprasanth04` · Repository: `hydrasight` · Workflow: `release.yml`
- Environment: **blank** — the workflow deliberately does *not* pin a GitHub
  environment. If you ever add `environment: pypi` to `publish-pypi`, name
  `pypi` in the publisher form too; the two must match exactly.

For a first release of a *new* project name, a pending publisher auto-creates
the project on the first successful publish.

## Verifying a release

```bash
pip install hydrasight==X.Y.Z        # or: pipx install
python -c "import hydrasight; print(hydrasight.__version__)"
```

Then confirm the GitHub Release page shows `X.Y.Z` with `hydrasight-X.Y.Z-py3-none-any.whl`
and `hydrasight-X.Y.Z.tar.gz` attached, and the Actions run for the tag is
all-green.
