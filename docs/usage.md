# Usage

## REPL commands

| Command | Description |
| --- | --- |
| `autopwn <ip>` | Full automated engagement against an authorized target |
| `scan <ip>` | Deep port/service scan (`-sV -sC`, full range) |
| `/run <action>` | Explicit single action, e.g. `/run check smb vuln on 10.0.0.5` |
| `/ask <question>` | Ask the assistant (conversational; never runs tools) |
| `authorize [ip\|cidr …]` | Show scope, or attest authorization for a scope |
| `roe` | Show the active Rules of Engagement |
| `findings` / `ports` / `vulns` / `creds` / `hashes` / `sessions` | Inspect results |
| `verify` | Re-verify findings against the target |
| `suggest` | Suggest next actions / access paths |
| `plan` | Show the engagement plan (dry-run) |
| `conclusion` | Classify and show the engagement outcome |
| `save [path]` | Save findings as JSON |
| `report <ip>` | Generate a PDF report |
| `sessions` / `resume <id>` | List / resume saved engagement sessions |
| `mode confirm\|auto\|never` | Set NL execution mode |
| `verbose 0..3` | Set verbosity |
| `status` / `config` / `stats` / `history` / `clear` | Diagnostics & state |
| `abort` | Abort the running engagement |
| `exit` / `quit` | Leave the shell |

`authorize` is available in tab-completion.

## Typical session

```text
hydra·sight › authorize 10.10.10.0/24
attest › I AUTHORIZE
hydra·sight › autopwn 10.10.10.15
hydra·sight › verify
hydra·sight › conclusion
hydra·sight │ report 10.10.10.15
```

## Safety reminders

- Plain conversational text never executes tools; use `/run` for explicit
  actions.
- Every blocked or allowed command is recorded in `hydrasight_audit.jsonl`.
- Nothing runs against a target outside the ROE ∩ authorization intersection.
