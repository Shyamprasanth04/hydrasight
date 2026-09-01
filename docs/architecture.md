# Architecture

HydraSight is layered so that safety policy lives in a small number of
well-tested chokepoints.

## Layers

- **CLI** (`cli/`) — the REPL (`shell.py`), handler delegation
  (`shell_handlers.py`), and Rich rendering (`shell_renderer.py`, `display.py`).
  The shell owns the loop; handlers own the logic.
- **Config** (`config/`) — default constants and the four-source loader.
- **Core** (`core/`) — the engagement `Engine`, `CommandBuilder`, action
  `registry`, `planner`, `profiles`, and hash-cracking logic (`hash_crack.py`).
- **Services** (`services/`) — orchestration glue: `Dispatcher` (the execution
  chokepoint), AI clients, `CommandRouter`, `VerifierService`,
  `SessionManager`, and the `post_access/` handler package.
- **Security** (`security/`) — `command_sanitizer`, `authorization`, and the
  `audit` trail.
- **Integrations** (`integrations/`) — the Kali REST client, Exploit-DB lookup.
- **Models** (`models/`) — findings, ROE, commands, planner state, timeline.
- **Reporting** (`reporting/`) — JSON/PDF reporters, remediation, outcome
  classification.

## The execution chokepoint

All command execution flows through `Dispatcher.dispatch()`, which normalizes
every input shape to `(tool, args, prebuilt)` and runs:

```text
validate_tool_call → render → validate_built_command → ROE ∩ authorization gate → KaliAPI
```

The gate is the only place scope is enforced, so policy cannot be bypassed by
adding a new entry point. The `Engine`, shell handlers, and NL pipeline all
funnel through it.

## Post-exploitation package

`services/post_access/` decomposes the post-access logic into focused handlers
(`MeterpreterHandler`, `ShellHandler`, `SSHAccessHandler`, `FTPAccessHandler`,
`WebAdminHandler`) behind a factory. The public import path
(`from hydrasight.services.post_access import ...`) is preserved.

## Data flow

```text
Ollama (LLM)  ──plans──▶  Engine/Planner ──▶ Dispatcher ──▶ Kali MCP ──▶ target
                                ▲                                       │
                                └──────── findings ingest ◀── output ───┘
```
