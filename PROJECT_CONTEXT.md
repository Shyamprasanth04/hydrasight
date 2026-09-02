# HydraSight — Project Context & Developer Reference

> **Version:** 4.0.0  
> **Type:** Python CLI — AI-assisted offensive security orchestration framework  
> **Status:** Active development. Phase 1–4 complete. 797/797 tests passing.  
> **Default local model:** `qcwind/qwen3-8b-instruct-Q4-K-M:latest` (Ollama)

---

## Purpose

HydraSight is a local, interactive penetration-testing assistant designed for **authorized lab environments**. It connects a local LLM (via Ollama) to a [Kali Linux MCP server](https://www.kali.org/blog/kali-linux-model-context-protocol-server/) (`/api/command`) and orchestrates security tools (nmap, enum4linux, smbclient, hydra, msfconsole, gobuster, nikto, etc.) through a typed, safety-gated dispatch layer.

**It is NOT:**
- A general-purpose chatbot
- A cloud service
- A tool for unauthorized scanning

**It IS:**
- A stateful REPL operator console
- An AI planner that proposes actions before running them
- A framework you can extend with new tool integrations

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| UI | Rich (terminal REPL with panels, tables, spinner) |
| AI | Ollama (local LLM — default: `qcwind/qwen3-8b-instruct-Q4-K-M:latest`) via HTTP `/api/chat` |
| Tool backend | Kali Linux MCP server (`/api/command`, default port 5000) |
| PDF reports | ReportLab |
| Package | `pyproject.toml`, editable install `pip install -e ".[dev]"` |
| Tests | pytest (665 tests, no network, all mocked) |
| Lint/CI | ruff (lint + format), pylint (≥9.0), mypy |

---

## Repository Layout

```
hydrasight/
├── hydrasight/                  ← main Python package
│   ├── __main__.py              ← entry point (python -m hydrasight)
│   ├── cli/
│   │   ├── shell.py             ← MAIN REPL loop — all user interaction
│   │   └── display.py           ← Rich console helpers (div, ok, warn, err, ...)
│   ├── config/
│   │   ├── defaults.py          ← P (colour tokens), PHASE_DEFS, TOOL_TIMEOUTS,
│   │   │                           CHAT_SYSTEM_PROMPT, SYSTEM_PROMPT, BANNER
│   │   └── loader.py            ← loads hydrasight.json + env vars
│   ├── core/
│   │   ├── engine.py            ← engagement orchestration engine (run, _ask_and_run,
│   │   │                           _plan_phases, _exploitation_phase, _post_exploit_phase)
│   │   └── planner.py           ← EngagementPlanner, EngagementBranch, EngagementPlan
│   ├── integrations/
│   │   ├── kali_api.py          ← HTTP client for kali-server-mcp (/api/command, /health)
│   │   ├── exploit_db.py        ← static CVE → Metasploit module map
│   │   └── exploit_suggestion.py← ExploitSuggestionProvider (confidence-scored candidates)
│   ├── models/
│   │   ├── findings.py          ← Findings — shared state object (ports, vulns, creds,
│   │   │                           hashes, sessions, timeline, host_info)
│   │   ├── finding_record.py    ← FindingRecord — typed, confidence-scored finding
│   │   ├── planner_state.py     ← PlannerState — memory/retry awareness across phases
│   │   └── roe.py               ← RulesOfEngagement — allowed targets, blocked ports/modules,
│   │                               approval gates, kill switch
│   ├── parsers/
│   │   └── base_parser.py       ← Parser — static helpers route tool output to findings fields
│   ├── reporting/
│   │   ├── json_reporter.py     ← save findings as JSON
│   │   ├── pdf_reporter.py      ← generate_pdf() — dark ReportLab PDF with findings tables
│   │   └── remediation.py       ← per-finding remediation advice
│   ├── services/
│   │   ├── ai_client.py         ← AIClient — orchestration LLM (tool-call extraction)
│   │   ├── chat_ai_client.py    ← ChatAIClient — conversation-only LLM (no tool calls)
│   │   ├── chat_controller.py   ← ChatController — safe conversational path + fake-exec guard
│   │   ├── command_router.py    ← CommandRouter — BUILTIN / ASK / RUN / CHAT classification
│   │   ├── intent_classifier.py ← IntentClassifier — pure regex NL classification
│   │   ├── intent_router.py     ← route_intent() — maps NL to pre-built tool_call dicts
│   │   ├── action_planner.py    ← ActionPlanner — builds PendingAction from IntentResult
│   │   ├── confirmation_manager.py ← ConfirmationManager — yes/no pending action state
│   │   ├── execution_policy.py  ← ExecutionPolicy — confirm / auto / never modes
│   │   ├── dispatcher.py        ← Dispatcher — executes tool_call dicts via KaliAPI
│   │   ├── post_access/         ← PostAccessHandler package — Meterpreter, Shell, SSH, FTP, WebAdmin
│   │   └── verifier.py          ← VerifierService — second-pass targeted finding verification
│   └── utils/
│       ├── ip_utils.py          ← IP validation, CIDR checks, dedup_ports
│       └── time_utils.py        ← ts() timestamp helper
├── tests/                       ← 797 pytest tests (all offline, all mocked)
│   ├── test_command_sanitizer.py ← security gate (largest, 134 tests)
│   ├── test_command_router.py   ← CommandRouter classification tests
│   ├── test_engine.py           ← engagement engine: recon/planning/exploit/hash-crack
│   ├── test_nl_pipeline.py      ← NL intent pipeline end-to-end tests
│   ├── test_dispatcher.py       ← Dispatcher command-building tests
│   ├── test_exploit_suggestion.py ← ExploitSuggestionProvider tests
│   ├── test_finding_record.py   ← FindingRecord confidence/severity tests
│   ├── test_findings.py         ← Findings state object tests
│   ├── test_ip_utils.py         ← IP/CIDR validation tests
│   ├── test_parser.py           ← Parser output parsing tests
│   ├── test_phase4.py           ← Phase 4 feature tests (plan, suggest, conclusion)
│   ├── test_planner_state.py    ← PlannerState memory/retry tests
│   ├── test_post_access.py      ← PostAccessHandler tests
│   └── test_roe.py              ← RulesOfEngagement tests
├── hydrasight.json              ← runtime config (git-ignored; copy from .example)
├── hydrasight.json.example      ← commit-safe config template
├── hydrasight.roe.json          ← (optional, git-ignored) rules of engagement scope
├── pyproject.toml               ← build, lint, test config
└── README.md                    ← user-facing quick start
```

---

## Core Concepts

### 1. Mode Separation (Safety Contract)

HydraSight enforces **strict mode separation** — every input is classified before any AI or tool call:

```
CommandRouter.classify(raw_input)
  → BUILTIN   (autopwn, scan, verify, plan, ...)   → built-in handler, no AI
  → /ask ...  (explicit chat prefix)               → ChatController, NEVER tools
  → /run ...  (explicit tool prefix)               → route_intent(), tool allowed
  → CHAT      (everything else)                    → NL intent pipeline
```

The NL intent pipeline (`_on_bare_text`) then runs:
1. Confirmation check (is this a `yes/no` reply?)
2. `IntentClassifier` → deterministic regex classification
3. Operational meta-intent check (verify/plan/suggest/conclude)
4. `ActionPlanner` → build `PendingAction`
5. `ExecutionPolicy` → apply `confirm | auto | never` mode
6. Dispatch to: chat / propose / execute / explain / plan

### 2. Intent Classification

`IntentClassifier` is **pure regex, zero AI calls**. It returns an `IntentResult` with:

| Intent | Examples |
|---|---|
| `CHAT` | `hey`, `thanks`, greetings |
| `EXPLAIN` | `what is smb signing`, `how does nmap work` |
| `PLAN` | `plan`, `dry run`, `show roadmap` |
| `EXECUTE_ACTION` | `run nmap on 10.0.0.1`, `check smb shares on 10.x` |
| `CLARIFY` | `check smb` (no IP), ambiguous requests |
| `EXECUTE_PLAN` | `do all planned stuff`, `run the plan`, `continue engagement` |
| `VERIFY_FINDINGS` | `verify findings`, `check confirmations` |
| `SHOW_SUGGESTIONS` | `suggest next step`, `what next`, `next move` |
| `SHOW_CONCLUSION` | `conclusion`, `summarize outcome`, `what did we find` |

### 3. Tool Hints and Routing

The `tool_hint` field drives which action is built:

| Hint | Tool | Command |
|---|---|---|
| `nmap_scan` | nmap | `nmap -sV -sC -p <ports> <target>` |
| `smb_check` | nmap script | `nmap --script smb-vuln-ms17-010,smb-os-discovery -p 445 <target>` |
| `smb_enum` | enum4linux | `enum4linux -S <target> 2>&1 \| head -150` |
| `smbclient_enum` | smbclient | `smbclient -L //<target> -N 2>&1 \| head -40` |
| `ftp_check` | nmap script | `nmap --script ftp-anon,ftp-vuln* -sV -p 21 <target>` |
| `ssh_check` | nmap script | `nmap --script ssh-auth-methods,ssh2-enum-algos -p 22 <target>` |
| `vuln_scan` | nmap vuln | `nmap -sV --script vuln -T4 -Pn --script-timeout 60s <target>` |
| `dir_enum` | gobuster | `gobuster dir -u http://<target> -w <wordlist>` |
| `autopwn` | engine | full adaptive engagement via `engine.run()` |

**SMB routing priority order** (newest — prevents drift to wrong tool):
1. `smbclient` keyword → `smbclient_enum`
2. `smb enum|enumeration|list shares|enum4linux|netbios enum` → `smb_enum`
3. `smb` + enumeration words → `smb_enum`
4. `smb` alone → `smb_check`
5. `vuln` keywords → `vuln_scan`

### 4. Findings State

`Findings` is the **shared mutable state** object. It lives on `Shell` and is passed to `Engine`, `Dispatcher`, `Parser`, `VerifierService`, and reporters.

Key fields:
```python
findings.ports          # list[dict]  — {port, proto, service, version}
findings.vulns          # list[dict]  — {name, severity, cve, description}
findings.credentials    # list[dict]  — {kind, username, secret, source}
findings.hashes         # list[dict]  — {username, ntlm, cracked}
findings.sessions       # list[dict]  — {id, target, uid, exploit}
findings.dirs           # list[dict]  — web paths found
findings.timeline       # list[dict]  — {ts, phase, event}
findings.finding_records # list[FindingRecord] — typed, confidence-scored
findings.target         # str | None  — current target IP
findings.overall_risk   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
findings.has_data       # bool        — True if any field populated
```

### 5. Rules of Engagement (ROE)

`hydrasight.roe.json` (optional):
```json
{
  "allowed_targets": ["10.0.2.0/24"],
  "blocked_ports": [22],
  "blocked_modules": ["exploit/windows/smb/ms17_010_eternalblue"],
  "require_approval_for": ["EXPLOIT", "POST_EXPLOIT"],
  "max_runtime_minutes": 60,
  "max_threads": 4,
  "kill_switch": false
}
```

If absent, permissive defaults are loaded. Every action is checked against ROE before execution.

### 6. PlannerState (Memory)

`PlannerState` gives the engine memory across phases:
- Tracks which phases have run
- Records credential attempts (avoids retrying failed creds)
- Records dead paths (avoids redundant scans)
- Feeds `EngagementPlanner.build()` for branch selection

### 7. Two AI Clients (Isolated)

| Client | Purpose | System Prompt | Tool Calls? |
|---|---|---|---|
| `AIClient` | Orchestration (Engine only) | Security JSON tool-call prompt | Yes — extracts `{"tool": ..., "args": ...}` |
| `ChatAIClient` | Conversation (ChatController only) | `CHAT_SYSTEM_PROMPT` — forbids JSON | Never |

These two clients have **completely separate message histories** and never interact.

---

## Key Design Decisions and Constraints

### What must NEVER change
- `ChatController` must **never** call `dispatcher.dispatch()` or `kali.*`
- `IntentClassifier` must remain **zero AI calls** — pure regex
- `_on_bare_text()` must check meta-intents **before** policy dispatch
- Arbitrary shell passthrough is **permanently disabled** — only whitelisted named actions

### Fake-Execution Guard
`ChatController.chat()` checks the model's response for action-claim phrases like `"I will begin"`, `"Starting now"`, `"Let's proceed"`. If found, it replaces the response with a safe message listing real executable actions. This prevents the AI from narrating fake tool runs.

### Execution Mode
Controlled via `mode confirm|auto|never` in the REPL or `execution_mode` in config:
- `confirm` — default; proposes action and waits for `yes/no`
- `auto` — runs immediately if confidence ≥ 80%
- `never` — explains/suggests only, never executes from NL

---

## Development Phases (History)

| Phase | What was built |
|---|---|
| Phase 1 | Modular refactor: parser, dispatcher, findings, AI client, shell, reporting. 93 tests. |
| Phase 2 | ROE model, `FindingRecord` + confidence scoring, `VerifierService`, `PlannerState` |
| Phase 3 | `ExploitSuggestionProvider`, `PostAccessHandler` (SSH/FTP/Web/Meterpreter), branch-aware planning, PDF polish |
| Phase 4 | `suggest`/`plan`/`conclusion` commands, `FTPAccessHandler`, `WebAdminHandler`, `_run_web_login`, mode system, README |
| Phase 4.5+ | NL intent pipeline refactor — `IntentClassifier`, `ActionPlanner`, `ConfirmationManager`, `ExecutionPolicy`, `CommandRouter`, `ChatController` isolation |
| Current | SMB routing fixes, `smbclient_enum` action, operational meta-intents (`EXECUTE_PLAN`, `VERIFY_FINDINGS`, `SHOW_SUGGESTIONS`, `SHOW_CONCLUSION`), stateful `_chat_context()`, fake-exec guard |

---

## Configuration Reference

`hydrasight.json` (git-ignored; copy `hydrasight.json.example`):
```json
{
  "ollama_url":       "http://localhost:11434",
  "kali_api_url":     "http://127.0.0.1:5000",
  "model":            "qcwind/qwen3-8b-instruct-Q4-K-M:latest",
  "context_size":     8192,
  "max_retries":      3,
  "retry_delay":      2.0,
  "verbosity":        1,
  "log_file":         "hydrasight.log",
  "output_dir":       "hydrasight_output",
  "lport":            4444,
  "token_budget":     6000,
  "auto_pdf":         true,
  "auto_save":        true,
  "scan_range":       "1-1000",
  "deep_scan_range":  "1-65535",
  "wordlist":         "/usr/share/wordlists/dirb/common.txt",
  "rockyou_path":     "/usr/share/wordlists/rockyou.txt",
  "execution_mode":   "confirm"
}
```

Tool-level HTTP timeouts (`defaults.py`):
```python
TOOL_TIMEOUTS = {
    "nmap_scan":     600,
    "nikto_scan":    220,
    "gobuster_scan": 300,
    "post_exploit":  420,
    "smb_enum":      240,   # increased for lab environments
    "ssh_brute":     600,
    "ftp_brute":     600,
    "whatweb_scan":   60,
    "run_command":   300,
}
```

---

## Test Suite

Run all tests (no network required, all mocked):
```bash
python -m pytest tests/ -q -p no:ethereum
# 665 passed
```

Key test files:
- `test_command_sanitizer.py` — largest (134 tests): security gate validation
- `test_command_router.py` — CommandRouter classification (84 tests)
- `test_engine.py` — engagement engine lifecycle, planning, exploitation, hash cracking, ROE gates
- `test_nl_pipeline.py` — intent classification, NL routing, shell integration, fake-exec guard
- `test_phase4.py` — plan/suggest/conclusion commands, planner integration
- `test_roe.py` — ROE model validation, CIDR checks, kill switch
- `test_finding_record.py` — FindingRecord confidence scoring, severity ranking
- `test_planner_state.py` — PlannerState memory, dead paths, credential tracking

---

## Adding a New Tool Action

Dispatch is now unified: every input shape is normalized by
`Dispatcher._resolve()`, validated, rendered by a single `_render()`
path (which delegates spec-building to `ActionPlanner._build_spec()`),
then validated again. There is no per-tool branch in `dispatch()` to
maintain.

1. **`core/builtin_actions.py`** — register an `ActionDefinition` (id, executable, default timeout, ROE category)
2. **`services/intent_classifier.py`** — add a regex pattern to `_tool_hint()` returning the new hint
3. **`services/action_planner.py`** — add an `elif action_id == "new_id"` branch in `_build_spec()` returning a `CommandSpec`
4. **`services/intent_router.py`** — add a routing entry mapping NL keywords to the new action id
5. **`security/command_sanitizer.py`** — add the action id to `_TOOL_VALIDATORS` (reuse `_generic_target_validator` for simple IP-target tools)
6. **`config/defaults.py`** — add `TOOL_TIMEOUTS["new_id"] = <seconds>` if the registry default is unsuitable
7. **Tests** — classification in `test_nl_pipeline.py`, command string in `test_dispatcher.py`, sanitizer allow/deny in `test_command_sanitizer.py`

---

## Running HydraSight

```bash
# Install
pip install -e ".[dev]"

# Start Ollama (local host)
ollama serve
ollama pull qcwind/qwen3-8b-instruct-Q4-K-M:latest

# Start Kali MCP server (on Kali VM)
kali-linux-mcp --transport sse

# Run
python -m hydrasight

# First session
hydrasight › status                          # health check
hydrasight › autopwn 10.129.74.47           # full engagement
hydrasight › scan 10.129.74.47              # port scan only
hydrasight › verify                         # verify findings
hydrasight › suggest                        # ranked exploit candidates
hydrasight › plan                           # dry-run roadmap
hydrasight › conclusion                     # engagement summary
hydrasight › report 10.129.74.47           # generate PDF

# NL interface (execution_mode = confirm)
hydrasight › enumerate smb shares on 10.129.74.47      → proposes enum4linux -S
hydrasight › list shares using smbclient on 10.x       → proposes smbclient -L
hydrasight › verify findings                            → runs _run_verify()
hydrasight › do all planned stuff                       → runs engine.run()
hydrasight › suggest next step                          → shows ranked suggestions
hydrasight › conclusion                                 → shows outcome summary
```

---

## Contacts / Ownership

- **Author:** Shyam
- **Repository:** https://github.com/Shyamprasanth04/hydrasight
- **Default local model:** `qcwind/qwen3-8b-instruct-Q4-K-M:latest` (Ollama)
- **Authorized use only.** Do not scan systems without explicit written permission.
