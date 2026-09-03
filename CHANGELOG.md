# Changelog

All notable changes to HydraSight are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.1] — 2026-09-03

### Fixed
- `help` reference omitted the **`authorize`** command (the mandatory
  scope attestation) and **`roe`**; added a dedicated `AUTHORIZATION`
  section above `ENGAGEMENT` so the first step of any engagement is
  discoverable.
- `help` now lists `resume` and documents the `exit / quit` synonym.

### Changed
- README: bridge setup updated for current Kali packaging
  (`sudo apt install mcp-kali-server`, run `kali-server-mcp`) — the pip-era
  `--transport sse` invocation no longer matches the apt binary.
- README: console OS support restated honestly — verified on Windows in
  addition to Linux (execution still happens on the Kali bridge).

## [4.1.0] — OBSIDIAN (2026-09-02)

Evolves HydraSight into an installable, trustworthy offensive-security product.

### Security & accountability (highest priority)

- **Mandatory authorization attestation** before any scan: `authorize <cidr>` →
  type `I AUTHORIZE` interactively, or a pre-signed
  `hydrasight.authorization.json` for CI/CTF. Enforced in the `Dispatcher` and
  every shell execution path; **deny by default**.
- **Tamper-evident audit trail** — append-only, SHA-256 hash-chained JSONL log
  (`hydrasight_audit.jsonl`) of every proposed/allowed/blocked command, with
  `AuditLogger.verify()` integrity checking and automatic secret redaction.
- **ROE ∩ authorization scope** enforced at the single dispatch chokepoint — a
  target must satisfy both the Rules-of-Engagement envelope and the operator
  attestation; neither can widen the other. The ROE kill-switch blocks dispatch.

### Packaging & onboarding

- Single-sourced version (`4.1.0`) with full PyPI metadata; `python -m build`
  produces a valid sdist + wheel.
- Docker image (non-root console, no offensive tools baked in) + docker-compose
  with a Kali MCP backend; Makefile with install/lint/typecheck/test/coverage/
  build/docs targets.
- MkDocs Material documentation site (builds `--strict`); CHANGELOG; CODEOWNERS.
- CI: ruff + mypy (strict function contracts) + pylint + pytest with a 75%
  branch-coverage floor + a strict docs job. `release.yml` publishes to PyPI via
  trusted publisher (OIDC) on `v*` tags and publishes a GitHub Release.

### Reliability & architecture

- Broad `except Exception` at network/IO boundaries narrowed to specific types;
  genuine last-resort boundaries are marked and logged.
- `post_access.py` (617 lines) decomposed into a focused package (public import
  path preserved); hash-crack logic extracted to `core/hash_crack.py`;
  engagement-outcome classification extracted to `reporting/outcome.py`.
- Fixed: `check_target` false-positive on "100% packet loss"; `save_json`
  leaking `ValueError` on invalid paths.
- Added unit tests; final shipped suite: **797 tests, 75.75% branch coverage**
  (enforced as the CI `--cov-fail-under=75` floor).
- The 617-line shadowed legacy `services/post_access.py` left by the package
  refactor was removed before tagging, and release docs were aligned to the
  shipped state.
- Shipped: published to PyPI via **OIDC trusted publishing** (zero API tokens)
  with an attached GitHub Release.

### Public API notes

REPL commands and configuration keys remain backward-compatible; `operator` is
added as a new config key. Internal module layouts changed (`post_access`
package, `hash_crack`, `outcome`) but public import paths are preserved.

## [4.0.0]

- Initial professional release: AI-orchestrated engagement engine, command
  sanitizer, Rules of Engagement, natural-language mode separation, and
  JSON/PDF reporting.

[4.1.0]: https://github.com/Shyamprasanth04/hydrasight/releases/tag/v4.1.0
[4.0.0]: https://github.com/Shyamprasanth04/hydrasight/releases/tag/v4.0.0
