# HydraSight

**AI-assisted, authorization-gated offensive-security orchestration.**

HydraSight drives a Kali backend (via the `kali-server-mcp` REST bridge) and a
local LLM (Ollama) to plan, execute, verify, and report on authorized
penetration tests. It is built around three non-negotiable safety properties:

1. **Deny by default.** No command reaches a target until an operator has
   explicitly attested authorization for that scope.
2. **A single enforcement chokepoint.** Every command is validated, scope-checked
   against both the Rules of Engagement *and* the operator attestation, and
   audited in one place (`Dispatcher`).
3. **A tamper-evident audit trail.** Every allow/block decision is written to an
   append-only, SHA-256 hash-chained JSONL log that can be verified at any time.

> ⚠️ **Authorized testing only.** HydraSight is intended for systems you own or
> have explicit written permission to test. Unauthorized use is illegal.

## Why HydraSight?

- **LLM orchestration with guardrails** — plain English never executes tools;
  only explicit `/run` actions and confirmed plans dispatch, and every tool call
  is validated by a strict command sanitizer.
- **Accountability** — mandatory authorization attestation plus a hash-chained
  audit log with automatic secret redaction.
- **Reporting** — JSON engagement exports and PDF reports out of the box.
- **Installable** — a real PyPI package, a non-root Docker image, and a
  docker-compose stack with a Kali bridge.

## Quick links

- [Getting Started](getting-started.md)
- [Security Model](security.md)
- [Authorization & Audit](authorization-audit.md)
- [Rules of Engagement](rules-of-engagement.md)
- [Usage](usage.md)

## License

Released under the [MIT License](https://github.com/Shyamprasanth04/hydrasight).
