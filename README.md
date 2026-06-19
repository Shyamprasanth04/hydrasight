# HydraSight

[![CI](https://github.com/Shyamprasanth04/hydrasight/actions/workflows/ci.yml/badge.svg)](https://github.com/Shyamprasanth04/hydrasight/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> AI-orchestrated offensive security assessment framework for authorized lab environments.

**HydraSight is for authorized testing only.** Do not use against systems you do not own or have explicit written permission to test.
See our [Security Policy](SECURITY.md) and [Contributing Guidelines](CONTRIBUTING.md).

---

## What is HydraSight?

HydraSight is a local, interactive CLI framework that connects a **local LLM** (via [Ollama](https://ollama.com)) to a **[Kali Linux MCP server](https://www.kali.org/blog/kali-linux-model-context-protocol-server/)** and orchestrates penetration testing tools through a stateful, safety-gated dispatch layer.

It is designed for security practitioners running structured assessments in isolated lab environments. It is not a product, not a cloud service, and not a chatbot.

---

## Features

| Feature | Description |
|---|---|
| **Natural language interface** | Describe what you want — HydraSight classifies, proposes, confirms, then executes |
| **Strict mode separation** | Chat never dispatches tools. `/run` and `autopwn` are the only execution paths |
| **Stateful REPL** | Persistent findings, timeline, credentials, sessions across a full engagement |
| **Adaptive planner** | Branch-aware engagement plans: recon-only, validation, credential-led, exploit-led, post-access |
| **Rules of Engagement** | Scope via `hydrasight.roe.json` — allowed targets, blocked ports, approval gates, kill switch |
| **Finding verification** | Second-pass targeted probes to confirm or deny CRITICAL/HIGH findings |
| **Confidence scoring** | Every finding and suggestion carries a 0.0–1.0 confidence score |
| **Dry-run planning** | `plan` and `suggest` show the full intent before anything runs |
| **Generic access paths** | SSH credential reuse, FTP enumeration, web admin login — not just Metasploit |
| **Planner memory** | Avoids repeated dead paths; tracks credential attempts across phases |
| **PDF reporting** | Dark-themed report with verified/unverified findings, confidence scores, remediation notes |
| **Fake-execution guard** | AI responses claiming to run tools are detected and replaced with safe clarifications |

---

## Repository Layout

```
hydrasight/
├── hydrasight/                  — main Python package
│   ├── cli/
│   │   ├── shell.py             — interactive REPL (all user interaction)
│   │   └── display.py           — Rich console helpers
│   ├── config/
│   │   ├── defaults.py          — colour tokens, phase defs, tool timeouts, system prompts
│   │   └── loader.py            — loads hydrasight.json + env vars
│   ├── core/
│   │   ├── engine.py            — engagement orchestration (run, plan, exploit, post-exploit)
│   │   └── planner.py           — EngagementPlanner, branch selection
│   ├── integrations/
│   │   ├── kali_api.py          — HTTP client for kali-server-mcp
│   │   ├── exploit_db.py        — CVE → Metasploit module map
│   │   └── exploit_suggestion.py— ExploitSuggestionProvider
│   ├── models/
│   │   ├── findings.py          — shared state (ports, vulns, creds, sessions, timeline)
│   │   ├── finding_record.py    — typed, confidence-scored finding
│   │   ├── planner_state.py     — engagement memory and retry tracking
│   │   └── roe.py               — Rules of Engagement model
│   ├── parsers/                 — tool output → findings fields
│   ├── reporting/               — JSON and PDF reporters
│   ├── services/
│   │   ├── ai_client.py         — orchestration LLM (tool-call extraction)
│   │   ├── chat_controller.py   — safe conversational path (never dispatches tools)
│   │   ├── intent_classifier.py — pure regex NL classification (zero AI calls)
│   │   ├── action_planner.py    — builds PendingAction from IntentResult
│   │   ├── dispatcher.py        — executes tool_call dicts via KaliAPI
│   │   ├── execution_policy.py  — confirm / auto / never modes
│   │   ├── verifier.py          — second-pass finding verification
│   │   └── post_access.py       — PostAccessHandler (Meterpreter, Shell, SSH, FTP, Web)
│   └── utils/                   — IP validation, timestamps
├── tests/                       — 393 offline pytest tests (all mocked)
├── .github/workflows/ci.yml     — GitHub Actions CI (Python 3.10/3.11/3.12)
├── hydrasight.json              — default runtime configuration
├── hydrasight.json.example      — safe config template (no real IPs)
├── pyproject.toml               — build, lint, and test configuration
├── PROJECT_CONTEXT.md           — developer reference and architecture detail
└── README.md                    — this file
```

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────┐
│                      Shell (REPL)                          │
│  autopwn │ scan │ verify │ plan │ suggest │ conclusion ...  │
└───────────────────────────┬────────────────────────────────┘
                            │
            ┌───────────────▼───────────────┐
            │           Engine              │
            │  EngagementPlanner            │ ← branch-aware planning
            │  PlannerState                 │ ← memory, retry tracking
            │  ROE Enforcer                 │ ← gates, limits, kill switch
            └────────┬──────────┬───────────┘
                     │          │
         ┌───────────▼──┐  ┌────▼──────────────────┐
         │  AIClient    │  │  Dispatcher            │
         │  (Ollama)    │  │  → KaliAPI (/api/cmd)  │
         └──────────────┘  └────────────────────────┘
                                      │
            ┌─────────────────────────▼──────────────────────┐
            │         ExploitSuggestionProvider               │
            │   metasploit │ ssh_access │ ftp │ web_login     │
            └─────────────────────────┬──────────────────────┘
                                      │
            ┌─────────────────────────▼──────────────────────┐
            │         PostAccessHandler                       │
            │   Meterpreter │ Shell │ SSH │ FTP │ WebAdmin    │
            └─────────────────────────┬──────────────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │   Findings (shared)      │
                         │   FindingRecord          │ ← typed, confidence-scored
                         │   VerifierService        │ ← second-pass probes
                         └─────────────────────────┘
```

---

## Installation

```bash
# Clone
git clone https://github.com/<your-username>/hydrasight.git
cd hydrasight

# Install (editable + dev tools)
pip install -e ".[dev]"
```

**Prerequisites:**

| Component | Where to run | Notes |
|---|---|---|
| Python 3.10+ | Your machine | `pip install -e ".[dev]"` |
| [Ollama](https://ollama.com) | Your machine | `ollama serve && ollama pull qwen2.5:7b` |
| [Kali MCP server](https://www.kali.org/blog/kali-linux-model-context-protocol-server/) | Kali VM | `kali-linux-mcp --transport sse` |

---

## Configuration

Copy the example config and edit for your environment:

```bash
cp hydrasight.json.example hydrasight.json
```

Key fields in `hydrasight.json`:

```json
{
  "ollama_url":    "http://localhost:11434",
  "kali_api_url":  "http://<kali-vm-ip>:<port>",
  "model":         "qwen2.5:7b",
  "lport":         4444,
  "execution_mode": "confirm"
}
```

Override any setting with an environment variable prefixed `HYDRA_`:

```bash
HYDRA_OLLAMA_URL=http://192.168.x.x:11434
HYDRA_MODEL=llama3.1:8b
HYDRA_EXECUTION_MODE=never
```

> **Never commit your `.env` or a `hydrasight.json` with real target IPs.** Both are in `.gitignore`.

---

## Rules of Engagement (optional)

Create `hydrasight.roe.json` to scope the engagement:

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

If no file is present, permissive defaults are used. All actions are checked against ROE before execution.

---

## First Run

```bash
python -m hydrasight

# Check system health
hydrasight › status

# See what the planner would do (dry run — no execution)
hydrasight › plan

# Begin a full engagement
hydrasight › autopwn 10.0.2.5
```

---

## Shell Commands

### Engagement
```
autopwn <ip>     Adaptive full-spectrum assessment
scan <ip>        Deep port scan only
abort            Abort current engagement
verify           Run second-pass verification on findings
```

### Planning (dry-run, nothing executes)
```
plan             Branch-aware engagement roadmap
suggest          Ranked access/exploit candidates with confidence
conclusion       Engagement outcome summary
```

### Natural Language
```
<any request>              Auto-classified — explains, proposes, or confirms before acting
/ask <question>            Force chat mode — never executes tools
/run <action>              Force tool routing, e.g. /run check smb on 192.168.1.10
yes / confirm              Confirm a proposed action
no / cancel                Cancel a proposed action
do all planned stuff       Resume full planned engagement
verify findings            Trigger second-pass verification
suggest next step          Show ranked suggestions
conclusion                 Show outcome summary
```

### Execution Mode
```
mode confirm     Always ask before NL-initiated execution (default)
mode auto        High-confidence requests execute automatically
mode never       NL never executes tools — explain/suggest only
```

### Data
```
findings         All discovered data
ports            Open ports
vulns            Vulnerabilities
creds            Captured credentials
hashes           NTLM hashes
sessions         Active access sessions
```

### Output
```
save [file]      Save findings to JSON
report <ip>      Generate PDF report
```

### System
```
status           System health check (Ollama + Kali MCP connectivity)
roe              Rules of Engagement status
config           Current configuration
stats            Session statistics
verbose 0-3      Output verbosity
clear            Reset session state
help             Full command reference
exit             Save and quit
```

---

## Running Tests

All 393 tests are offline — no Ollama, no Kali MCP server required:

```bash
python -m pytest tests/ -q -p no:ethereum
# 393 passed
```

---

## Current Status

| Component | Status |
|---|---|
| Core engine (run, plan, dispatch) | ✅ Complete |
| ROE model + enforcement | ✅ Complete |
| FindingRecord + confidence scoring | ✅ Complete |
| VerifierService (second-pass probes) | ✅ Complete |
| PlannerState (memory, retry tracking) | ✅ Complete |
| ExploitSuggestionProvider | ✅ Complete |
| PostAccessHandler (SSH, FTP, Web, Meterpreter) | ✅ Complete |
| Branch-aware engagement planner | ✅ Complete |
| `suggest` / `plan` / `conclusion` commands | ✅ Complete |
| Natural language intent pipeline | ✅ Complete |
| Operational meta-intents (execute\_plan, verify, suggest, conclude) | ✅ Complete |
| Fake-execution guard | ✅ Complete |
| PDF reporting (verified / confidence / exploit status) | ✅ Complete |
| GitHub Actions CI | ✅ Present |
| Multi-target / CIDR support | 🔲 Planned |
| Web UI / dashboard | 🔲 Not planned |

---

## License

MIT License — see [LICENSE](LICENSE).

**This software is for authorized security testing only.** The author assumes no liability for misuse. Use only against systems you own or have explicit written permission to test.
