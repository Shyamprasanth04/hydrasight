# Changelog

All notable changes to HydraSight are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The canonical changelog is
[`CHANGELOG.md`](https://github.com/Shyamprasanth04/hydrasight/blob/main/CHANGELOG.md)
in the repository root.

## 4.1.1

### Fixed
- `help` documents `authorize`, `roe`, `resume`, and the `exit / quit`
  synonym — new `AUTHORIZATION` section leads the reference.

### Changed
- Bridge setup for current Kali packaging: `sudo apt install mcp-kali-server`,
  start with `kali-server-mcp`.

## 4.1.0 — OBSIDIAN

### Security & accountability
- Mandatory **authorization attestation** before any scan (`authorize <cidr>` →
  type `I AUTHORIZE`, or a pre-signed `hydrasight.authorization.json` for CI).
  Enforced at the `Dispatcher` chokepoint and across shell execution paths;
  deny by default.
- **Tamper-evident audit trail** — append-only, SHA-256 hash-chained JSONL with
  `AuditLogger.verify()` integrity checking and automatic secret redaction.
- **ROE ∩ authorization scope** enforcement — a target must satisfy both the
  Rules-of-Engagement envelope and the operator attestation; ROE kill-switch
  blocks dispatch.

### Packaging & onboarding
- Single-sourced version and full PyPI metadata; `python -m build` produces
  sdist + wheel.
- Non-root Docker image + docker-compose (Kali MCP backend) + Makefile.
- MkDocs Material documentation site (builds `--strict`); CHANGELOG; CODEOWNERS.
- CI: ruff + mypy (strict function contracts) + pylint + pytest with a 75%
  branch-coverage floor and a strict docs job. `release.yml` publishes to PyPI
  via trusted publisher on `v*` tags and publishes a GitHub Release.
- One-line install: `pip install hydrasight` — the PyPI project was
  auto-created by the first trusted-publishing run (no manual registration).

### Reliability & architecture
- Broad `except Exception` at network/IO boundaries narrowed to specific types.
- `post_access.py` decomposed into a focused package (import path preserved);
  hash-crack logic extracted to `core/hash_crack.py`; engagement-outcome
  classification extracted to `reporting/outcome.py`.
- Fixed: `check_target` false-positive on "100% packet loss"; `save_json`
  leaking `ValueError`.

## 4.0.0

- Initial professional release: AI-orchestrated engagement engine, command
  sanitizer, Rules of Engagement, NL mode separation, JSON/PDF reporting.
