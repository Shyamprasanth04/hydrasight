# Security Model

HydraSight is an offensive-security tool, so safety and accountability are
designed in rather than bolted on.

## Defense in depth

```text
REPL / NL input
   │  (plain English NEVER executes tools)
   ▼
Intent classifier + execution policy
   │
   ▼
Command sanitizer  ── validates raw tool_call args (validate_tool_call)
   │
   ▼
Command builder    ── renders a typed command spec
   │
   ▼
Built-command validation (validate_built_command)
   │
   ▼
Scope gate: ROE ∩ authorization   ◄── single chokepoint in Dispatcher
   │              │
   │              └── AuditLogger: command_allowed / command_blocked
   ▼
KaliAPI (kali-server-mcp)
```

## Properties

- **Deny by default.** Without an authorization attestation, every target is
  denied. See [Authorization & Audit](authorization-audit.md).
- **Intersection, not union.** A target must satisfy **both** the Rules of
  Engagement envelope (`hydrasight.roe.json`) and the operator attestation.
  Neither can widen the other. See [Rules of Engagement](rules-of-engagement.md).
- **Kill switch.** An active ROE `kill_switch` blocks all dispatch.
- **Command sanitization.** Commands are validated before and after rendering;
  rejected commands are logged and never sent to the Kali backend.
- **Secret redaction.** Audit records scrub `sshpass -p`, inline URL
  credentials, and `password=`/`token=` style secrets before they touch disk.
- **Tamper-evident logs.** The audit trail is hash-chained; `AuditLogger.verify()`
  detects altered or deleted records.

## Mode separation

| Input | Behavior |
| --- | --- |
| bare text / `/ask` | Conversational — **never** dispatches tools |
| `/run <action>` | Explicit operator intent — routes to tools |
| builtins (`scan`, `autopwn`, …) | Direct commands |
| NL plan | Dry-run; never executes on its own |

The `execution_mode` config (`confirm` / `auto` / `never`) further constrains
natural-language dispatch, but the authorization gate always applies.
