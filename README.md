<div align="center">

<pre>
██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
███████║ ╚████╔╝ ██║  ██║██████╔╝███████║███████╗██║██║  ███╗███████║   ██║   
██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║╚════██║██║██║   ██║██╔══██║   ██║   
██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║███████║██║╚██████╔╝██║  ██║   ██║   
╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
</pre>

**AI-Assisted Offensive Security Orchestration — For Authorized Lab Environments**

[![Version](https://img.shields.io/badge/version-4.1.0-blue?style=for-the-badge&logo=github)](https://github.com/Shyamprasanth04/hydrasight/releases/tag/v4.1.0)
[![PyPI](https://img.shields.io/pypi/v/hydrasight?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/hydrasight/)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-797%20passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](./tests/)
[![CI](https://img.shields.io/badge/CI-ruff%20%7C%20mypy%20%7C%20pylint-success?style=for-the-badge)](./.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge)](./LICENSE)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20%28local%29-ff6b35?style=for-the-badge&logo=llama&logoColor=white)](https://ollama.com/)
[![Kali Linux](https://img.shields.io/badge/backend-Kali%20Linux%20MCP-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)

</div>

---

> [!CAUTION]
> **HydraSight is designed exclusively for use in authorized lab environments, CTF challenges, and penetration tests where explicit written permission has been granted.** Running security tools against systems you do not own or have authorization for is illegal and unethical. The author accepts no responsibility for misuse.

---

## What is HydraSight?

HydraSight is a **local, stateful, AI-assisted penetration testing REPL** that bridges a locally-running LLM (via [Ollama](https://ollama.com/)) to real security tools on a Kali Linux host. It acts as an intelligent operator console — classifying your natural language intent, proposing actions before executing them, enforcing a rules-of-engagement policy, and producing structured JSON and PDF reports.

It is **not** a chatbot. It is **not** a cloud service. It is a typed, safety-gated orchestration framework that keeps a human in the loop at every step.

```
hydrasight › enumerate smb shares on 10.129.74.47
 Proposing ──  enum4linux -a 10.129.74.47 2>&1 | head -n 150
 Confirm? [y/N]  y
 Running enum4linux ...
 ✔  Found 3 shares: IPC$, ADMIN$, Data
```

### What it is
- ✅ A stateful REPL operator console with persistent findings state
- ✅ An AI planner that proposes before executing — never surprises you
- ✅ An extensible framework: add a new tool in 6 well-defined steps
- ✅ 100% offline — no data leaves your machine

### What it is not
- ❌ A general-purpose chatbot
- ❌ A cloud-connected service
- ❌ An autonomous agent for unauthorized scanning

---

## Features

| Category | Details |
|---|---|
| **AI Layer** | Dual isolated clients — `AIClient` (tool-calling engine) and `ChatAIClient` (conversational only, never calls tools) |
| **Intent Classification** | Pure regex `IntentClassifier` — zero AI inference calls for routing decisions |
| **Execution Safety** | Three-mode policy: `confirm` (default), `auto` (≥80% confidence), `never` |
| **Rules of Engagement** | Per-engagement ROE file — allowed targets, blocked ports/modules, kill switch |
| **Tool Dispatch** | Whitelisted registry-backed actions only — no arbitrary shell passthrough |
| **Findings State** | Shared mutable state: ports, vulns, credentials, hashes, sessions, dirs, timeline |
| **Reporting** | Auto-generated JSON + PDF reports via ReportLab |
| **UI** | Rich terminal panels, tables, spinners — full REPL with history |
| **Test Suite** | 797 pytest tests, all offline, all mocked — no network required |
| **CI Gates** | `ruff` lint+format, `mypy` strict-ish types, `pylint` ≥ 9.0, pytest + coverage |

---

## Architecture

HydraSight enforces a strict **mode-separation safety contract**. Every input is classified before any AI call or tool execution occurs.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          hydrasight ›  <user input>                      │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    CommandRouter         │
                    │   .classify(raw_input)   │
                    └─┬──────────┬────────────┘
          ┌───────────┘          │           └─────────────────┐
          │ BUILTIN              │ CHAT                         │ /ask or /run
          │ (autopwn, scan…)     │ (bare NL text)               │
          ▼                      ▼                              ▼
  ┌───────────────┐   ┌──────────────────────┐      ┌───────────────────┐
  │  Built-in     │   │   NL Intent Pipeline  │      │  /ask → ChatCtrl  │
  │  Handler      │   │                       │      │  /run → route_    │
  │  (no AI)      │   │  1. Confirm check     │      │        intent()   │
  └───────────────┘   │  2. IntentClassifier  │      └───────┬───────────┘
                       │     (pure regex)      │              │
                       │  3. Meta-intent check │        ┌─────▼──────┐
                       │  4. ActionPlanner     │        │ ChatAI     │
                       │  5. ExecutionPolicy   │        │ Client     │
                       │  6. Dispatch          │        │ (NO tools) │
                       └──────────┬────────────┘        └────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
       ┌─────────────┐   ┌────────────────┐  ┌──────────────────┐
       │  ChatAI     │   │   Dispatcher   │  │  ActionPlanner   │
       │  (explain)  │   │  (execute cmd) │  │  (dry-run plan)  │
       └─────────────┘   └───────┬────────┘  └──────────────────┘
                                  │
                    ┌─────────────▼──────────────────┐
                    │  Security Gates                  │
                    │  1. ROE check (allowed_targets)  │
                    │  2. validate_tool_call()         │
                    │  3. CommandBuilder (typed spec)  │
                    │  4. validate_built_command()     │
                    └─────────────┬──────────────────┘
                                  │
                    ┌─────────────▼──────────────────┐
                    │  KaliAPI → /api/command          │
                    │  (Kali Linux MCP server)         │
                    └────────────────────────────────┘
```

### Two Isolated AI Clients

| Client | Purpose | Tool Calls | Message History |
|---|---|---|---|
| `AIClient` | Engine orchestration — extracts `{tool, args}` JSON | ✅ Yes | Engine-only |
| `ChatAIClient` | Conversational responses only | ❌ Never | Chat-only (separate) |

`ChatController` is **hardcoded** to never call `dispatcher.dispatch()`. A Fake-Execution Guard detects and blocks phrases like `"I will begin scanning"` or `"Starting now"` to prevent the chat LLM from impersonating tool execution.

### Intent Classification (Zero AI Calls)

The `IntentClassifier` uses pure regex pattern matching — no LLM inference:

| Intent | Triggers |
|---|---|
| `EXECUTE_ACTION` | Explicit verb + tool hint (`scan`, `enumerate`, `run nmap`…) |
| `VERIFY_FINDINGS` | `verify`, `confirm findings`, `double-check`… |
| `SHOW_SUGGESTIONS` | `suggest`, `next step`, `what should I try`… |
| `SHOW_CONCLUSION` | `conclude`, `summary`, `final report`… |
| `EXPLAIN` | `what is`, `explain`, `how does`… |
| `PLAN` | `plan`, `roadmap`, `dry run`… |
| `EXECUTE_PLAN` | `do all`, `run everything`, `execute plan`… |
| `CHAT` | Everything else → conversational response |

---

## Supported Tool Actions

Every action is whitelisted in the registry and rendered through a typed
`CommandSpec` — there is no raw shell passthrough.

| Action ID | Tool Executed | Description |
|---|---|---|
| `nmap_scan` | `nmap -sV -sC` | Service version + default script scan |
| `smb_check` | `nmap --script smb-vuln*` | SMB vulnerability checks |
| `smb_enum` | `enum4linux -a` | Full SMB/NetBIOS enumeration |
| `smbclient_enum` | `smbclient -L` | Share listing via smbclient |
| `ftp_check` | `nmap -p 21 --script ftp*` | FTP banner + anon-auth check |
| `ssh_check` | `nmap -p 22 --script ssh*` | SSH version + key exchange audit |
| `vuln_scan` | `nmap --script vuln` | Generic vulnerability script scan |
| `dir_enum` | `gobuster dir` | Web directory brute-force |
| `gobuster_scan` | `gobuster dir` | Gobuster scan driven by URL/wordlist args |
| `nikto_scan` | `nikto -h` | Web server vulnerability scan |
| `whatweb_scan` | `whatweb` | Web technology fingerprinting |
| `ssh_brute` | `hydra ssh://` | SSH credential brute-force |
| `ftp_brute` | `hydra ftp://` | FTP credential brute-force |
| `run_command` | allowlisted binaries | Internal use only — credential reuse / john hash cracking |
| `post_exploit` | `msfconsole` (RC via base64) | Metasploit exploit/auxiliary execution |
| `autopwn` | Engine orchestration | Full adaptive engagement sequence |

> **Note:** `run_command` and `post_exploit` are invoked internally by the
> engine/post-access handlers, never proposed directly from natural language.
> `run_command` is restricted to a fixed binary allowlist
> (nmap, gobuster, nikto, hydra, msfconsole, smbclient, sshpass, john, curl, …).

---

## Repository Layout

```
hydrasight/
├── hydrasight/                  # Main package
│   ├── cli/
│   │   ├── shell.py             # Main REPL loop (Rich UI)
│   │   ├── shell_handlers.py    # Built-in command handlers
│   │   ├── shell_renderer.py    # Output rendering helpers
│   │   └── display.py           # Rich panel/table formatters
│   ├── config/
│   │   ├── defaults.py          # DEFAULT_CONFIG, tool timeouts, allowed keys
│   │   └── loader.py            # Config merge: defaults → JSON → env vars
│   ├── core/
│   │   ├── engine.py            # Autopwn orchestration engine
│   │   ├── registry.py          # Tool action registry
│   │   ├── command_builder.py   # Typed CommandSpec → shell string builder
│   │   ├── builtin_actions.py   # register_builtins() — default tool definitions
│   │   └── profiles.py         # Scan intensity profiles (quick/full/stealth)
│   ├── integrations/
│   │   ├── kali_api.py          # KaliAPI — POST /api/command wrapper
│   │   ├── exploit_db.py        # ExploitDB search integration
│   │   └── exploit_suggestion.py # Confidence-scored exploit ranking
│   ├── models/
│   │   ├── commands.py          # ActionRequest, PendingAction, ExecutionRequest
│   │   ├── findings.py          # Findings container (shared mutable state)
│   │   ├── finding_record.py    # FindingRecord with full lifecycle transitions
│   │   ├── report_model.py      # ReportModel — normalized reporting buckets
│   │   ├── timeline.py          # TimelineEvent dataclass
│   │   ├── planner_state.py     # PlannerState for multi-step engagements
│   │   └── roe.py               # Rules of Engagement model
│   ├── parsers/
│   │   └── base_parser.py       # Output parser base + tool-specific parsers
│   ├── reporting/
│   │   ├── json_reporter.py     # JSON report generator
│   │   ├── pdf_reporter.py      # PDF report generator (ReportLab)
│   │   └── remediation.py       # Per-finding remediation advice
│   ├── security/
│   │   └── command_sanitizer.py # validate_tool_call(), validate_built_command()
│   ├── services/
│   │   ├── chat_controller.py   # Pure chat handler — hardcoded: no dispatch
│   │   ├── dispatcher.py        # ActionRequest/PendingAction → KaliAPI
│   │   ├── intent_classifier.py # Pure regex NL intent classifier
│   │   ├── intent_router.py     # NL phrase → tool + args routing table
│   │   ├── action_planner.py    # IntentResult → PendingAction + CommandSpec
│   │   ├── execution_policy.py  # confirm / auto / never policy enforcement
│   │   ├── ai_client.py         # AIClient — engine tool-calling LLM
│   │   ├── chat_ai_client.py    # ChatAIClient — conversational LLM only
│   │   ├── verifier.py          # Second-pass finding verification
│   │   ├── post_access/         # Post-exploitation handler package
│   │   ├── session_manager.py   # Session autosave/restore
│   │   └── context_builder.py   # LLM context window builder
│   └── utils/
│       ├── ip_utils.py           # IP validation, force_ip(), CIDR helpers
│       └── time_utils.py         # Elapsed time formatting
├── tests/                        # 797 pytest tests — all offline
│   ├── test_nl_pipeline.py       # 31 tests — NL intent classification
│   ├── test_command_router.py    # CommandRouter classification
│   ├── test_command_sanitizer.py # Security gate validation
│   ├── test_dispatcher.py        # Dispatcher command building
│   ├── test_phase4.py            # Full E2E engagement flow
│   ├── test_roe.py               # Rules of Engagement enforcement
│   ├── test_finding_record.py    # FindingRecord lifecycle transitions
│   ├── test_planner_state.py     # Multi-step planner state
│   ├── test_parser.py            # Tool output parsing
│   ├── test_pass3_refactor.py    # NL → correct action ID routing
│   ├── test_pass4_reporting.py   # Report model & finding normalization
│   ├── test_shell_refactor.py    # Shell handler integration
│   ├── test_ai_client_options.py # AIClient configuration
│   ├── test_command_builder.py   # CommandSpec → string rendering
│   ├── test_context_builder.py   # LLM context window construction
│   ├── test_exploit_suggestion.py # Exploit ranking
│   ├── test_findings.py          # Findings container operations
│   ├── test_ip_utils.py          # IP utility functions
│   ├── test_post_access.py       # Post-exploitation handlers
│   └── test_registry.py          # Action registry
├── hydrasight.json               # Runtime config (git-ignored — copied from example)
├── hydrasight.json.example       # Commit-safe config template
├── pyproject.toml                # Package definition + tool config
└── README.md
```

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Required |
| [Ollama](https://ollama.com/) | Latest | Runs on your host machine |
| Kali Linux | Rolling | VM or bare-metal |
| [kali-linux-mcp](https://github.com/digininja/kali-linux-mcp) | Latest | Installed on Kali |

### 1. Install

```bash
# From PyPI (recommended)
pip install hydrasight
```

For development — editable install with the full dev toolchain:

```bash
git clone https://github.com/Shyamprasanth04/hydrasight.git
cd hydrasight

# Install in editable mode with all dev dependencies
pip install -e ".[dev]"
```

### 2. Start Ollama & Pull Model

```bash
# Start the Ollama server (runs locally)
ollama serve

# Pull the default model (Qwen3 8B, Q4_K_M quantisation, ~5 GB)
ollama pull qcwind/qwen3-8b-instruct-Q4-K-M:latest
```

> Any Ollama-hosted chat model works — override with the `model` key in
> `hydrasight.json` or the `HYDRA_MODEL` environment variable. The
> orchestrator runs with low temperature (`think: false`) for reliable
> tool-call extraction; the chat client uses a slightly higher temperature.

### 3. Start the Kali MCP Server

On your Kali Linux VM or host:

```bash
# Install if not present
pip install kali-linux-mcp

# Start the MCP server (default: http://0.0.0.0:5000)
kali-linux-mcp --transport sse
```

### 4. Configure

Copy the example config and edit to match your environment:

```bash
cp hydrasight.json.example hydrasight.json
```

Key fields to update:

```json
{
  "ollama_url":   "http://localhost:11434",
  "kali_api_url": "http://<kali-vm-ip>:5000",
  "model":        "qcwind/qwen3-8b-instruct-Q4-K-M:latest",
  "execution_mode": "confirm"
}
```

> `hydrasight.json` is git-ignored (it may contain lab IPs). Commit-safe
> defaults live in `hydrasight.json.example`.

### 5. Launch

```bash
python -m hydrasight
```

You should see the Rich REPL prompt:

```
 HydraSight v4.1.0  ─  AI Offensive Security Console
 Ollama: ✔ ready  │  Kali API: ✔ ready
─────────────────────────────────────────────────────
hydrasight ›
```

---

## Usage

### Built-in Commands

| Command | Description |
|---|---|
| `autopwn <target>` | Launch a full adaptive engagement (scan → enum → exploit → verify) |
| `scan <target>` | Run a targeted port scan only |
| `verify` | Second-pass verification of all plausible findings |
| `suggest` | Display confidence-scored exploit candidates for current findings |
| `plan` | Generate a dry-run engagement roadmap without executing |
| `conclusion` | Print the full engagement outcome summary |
| `report <target>` | Generate a JSON + PDF report for the target |
| `status` | Health check: Ollama connection + Kali API connectivity |
| `mode confirm` | Set execution policy to confirm (default — prompts before every action) |
| `mode auto` | Set execution policy to auto (executes if AI confidence ≥ 80%) |
| `mode never` | Set execution policy to never (explains/suggests only — no execution) |
| `help` | Display the full command reference |
| `exit` | Quit HydraSight |

### Explicit Prefixes

| Prefix | Behaviour |
|---|---|
| `/ask <question>` | Forces conversational response — **never** triggers tool dispatch |
| `/run <nl phrase>` | Forces tool routing — bypasses CHAT classification |

### Natural Language Examples

```
hydrasight › enumerate smb shares on 10.129.74.47
  → Proposes: enum4linux -a 10.129.74.47 2>&1 | head -n 150

hydrasight › list shares using smbclient on 10.129.74.47
  → Proposes: smbclient -L //10.129.74.47 -N 2>&1 | head -n 40

hydrasight › run nmap on 10.129.74.47
  → Proposes: nmap -sV -sC 10.129.74.47

hydrasight › check ftp on 10.129.74.47
  → Proposes: nmap -p 21 --script ftp-anon,ftp-bounce 10.129.74.47

hydrasight › what is smb signing?
  → Chat response — no tool call, no dispatch

hydrasight › suggest next step
  → Ranked exploit candidates with confidence scores

hydrasight › do all planned stuff
  → Executes engine.run() — full engagement sequence
```

### Execution Modes

```
hydrasight › mode confirm    # Prompts for y/N before every tool run (default)
hydrasight › mode auto       # Auto-executes when AI confidence ≥ 80%
hydrasight › mode never      # Explains and suggests only — safe for demos
```

### Rules of Engagement

Create a `hydrasight.roe.json` file in your project root to enforce per-engagement constraints (this file is git-ignored — it is target-specific):

```json
{
  "allowed_targets": ["10.129.74.0/24", "192.168.56.0/24"],
  "blocked_ports":   [22],
  "blocked_modules": ["exploit/windows/smb/ms08_067_netapi"],
  "require_approval_for": ["EXPLOIT", "POST_EXPLOIT"],
  "max_runtime_minutes": 60,
  "max_threads": 4,
  "kill_switch": false
}
```

Phase IDs used in `require_approval_for` are uppercase: `RECON`, `FTP_CHECK`,
`SMB_CHECK`, `SSH_CHECK`, `WEB_*`, `VULN_SCAN`, `EXPLOIT`, `POST_EXPLOIT`,
`HASH_CRACK`. Every action is validated against the ROE before dispatch.
Actions targeting out-of-scope hosts are blocked and logged.

---

## Configuration Reference

HydraSight merges configuration in priority order: **environment variables > `.env` file > `hydrasight.json` > built-in defaults**.

| Key | Default | Description |
|---|---|---|
| `ollama_url` | `http://localhost:11434` | Ollama API endpoint |
| `kali_api_url` | `http://127.0.0.1:5000` | Kali MCP server URL |
| `model` | `qcwind/qwen3-8b-instruct-Q4-K-M:latest` | Ollama model name |
| `context_size` | `8192` | LLM context window (tokens) |
| `max_retries` | `3` | API call retry limit |
| `retry_delay` | `2` | Seconds between retries |
| `verbosity` | `1` | Log verbosity (0=quiet, 2=debug) |
| `log_file` | `hydrasight.log` | Log file path |
| `output_dir` | `hydrasight_output/` | Report and artifact output directory |
| `lport` | `4444` | Local listener port for reverse shells |
| `token_budget` | `6000` | Max tokens per LLM context window |
| `auto_pdf` | `true` | Auto-generate PDF at session end |
| `auto_save` | `true` | Auto-save findings JSON periodically |
| `scan_range` | `"1-1000"` | Default nmap port range |
| `deep_scan_range` | `"1-65535"` | Deep scan port range |
| `wordlist` | `/usr/share/wordlists/dirb/common.txt` | Gobuster wordlist path |
| `rockyou_path` | `/usr/share/wordlists/rockyou.txt` | Hydra wordlist path |
| `execution_mode` | `confirm` | `confirm` / `auto` / `never` |

**Environment variable overrides:**

```bash
export HYDRA_KALI_URL="http://192.168.56.10:5000"
export HYDRA_MODEL="qcwind/qwen3-8b-instruct-Q4-K-M:latest"
export HYDRA_VERBOSITY=2
```

---

## Tests

HydraSight has **797 pytest tests** — all fully offline, all network calls mocked.

```bash
# Run full test suite
python -m pytest tests/ -q -p no:ethereum

# Run with coverage
python -m pytest tests/ --cov=hydrasight --cov-report=term-missing -p no:ethereum

# Run a specific module
python -m pytest tests/test_nl_pipeline.py -v
```

### Test Coverage by Module

| Test File | Tests | Coverage Area |
|---|---|---|
| `test_command_sanitizer.py` | 134 | Security gate: tool call + built command validation |
| `test_command_router.py` | 84 | CommandRouter BUILTIN/CHAT/NL classification |
| `test_phase4.py` | 41 | Planner / post-access handler integration |
| `test_nl_pipeline.py` | 34 | NL intent classification end-to-end |
| `test_parser.py` | 35 | Tool output parsing (nmap, enum4linux, gobuster…) |
| `test_exploit_suggestion.py` | 33 | Confidence-scored exploit ranking |
| `test_engine.py` | 27 | Engagement engine: recon, planning, exploit, hash crack, ROE |
| `test_ai_client_options.py` | 27 | AIClient configuration and streaming |
| `test_finding_record.py` | 30 | FindingRecord lifecycle (CANDIDATE → VERIFIED → EXPLOITED) |
| `test_planner_state.py` | 28 | Multi-step PlannerState transitions |
| `test_shell_refactor.py` | 34 | Shell handler + renderer integration |
| `test_findings.py` | 25 | Findings container CRUD and separation |
| `test_context_builder.py` | 23 | LLM context window truncation |
| `test_post_access.py` | 23 | Post-exploitation handler flows |
| `test_ip_utils.py` | 19 | IP normalization, force_ip(), CIDR |
| `test_roe.py` | 30 | Rules of Engagement enforcement |
| `test_dispatcher.py` | 14 | Command building + unified dispatch path |
| `test_command_builder.py` | 6 | CommandSpec → safe shell string rendering |
| `test_pass3_refactor.py` | 8 | NL phrase → correct action ID routing |
| `test_pass4_reporting.py` | 5 | ReportModel normalization, finding buckets |
| `test_registry.py` | 5 | Action registry lookup and resolution |

> **Note:** The `-p no:ethereum` flag suppresses an unrelated `web3` pytest plugin import error present in some environments.

---

## Extending HydraSight — Adding a New Tool

Adding a new tool action requires touching 6 files. Here is a concrete example of adding an `ldap_enum` action:

**Step 1 — Register in `core/builtin_actions.py`:**
```python
registry.register(ActionDefinition(
    action_id="ldap_enum",
    description="LDAP enumeration via ldapsearch",
    executable="ldapsearch",
    arg_template=["-x", "-H", "ldap://{target}", "-b", "dc=domain,dc=com"],
    default_timeout=60,
))
```

**Step 2 — Add to `services/intent_classifier.py`:**
```python
# In the EXECUTE_ACTION pattern group:
(r"\bldap\b.*\benum\b|\bldap.?search\b", "ldap_enum"),
```

**Step 3 — Add spec builder in `services/action_planner.py`:**
```python
elif tool == "ldap_enum":
    return CommandSpec(executable="ldapsearch", args=[...])
```

**Step 4 — Add routing in `services/intent_router.py`:**
```python
{"keywords": ["ldap", "enumerate"], "tool": "ldap_enum", "priority": 5},
```

**Step 5 — Add timeout in `config/defaults.py`:**
```python
TOOL_TIMEOUTS = {
    ...
    "ldap_enum": 60,
}
```

**Step 6 — Write tests in `tests/test_<name>.py`:**
```python
def test_ldap_enum_routed_correctly():
    res = IntentClassifier().classify("enumerate ldap on 10.0.0.1")
    assert res.tool_hint == "ldap_enum"
```

---

## Security Design

HydraSight's safety architecture is layered by design. Each layer can independently block an action:

```
User Input
    │
    ├─ 1. Mode Separation ──── ChatController HARDCODED to never call dispatch()
    │                          Fake-Execution Guard blocks LLM role-play of tools
    │
    ├─ 2. ROE Enforcement ──── allowed_targets / blocked_ports / blocked_modules
    │                          kill_switch support
    │
    ├─ 3. validate_tool_call() ─ Argument-level sanitization before build
    │
    ├─ 4. CommandBuilder ────── Typed CommandSpec — no raw string interpolation
    │
    └─ 5. validate_built_command() ─ Pattern-based final command string audit
                                     before the command reaches KaliAPI
```

**Key safety invariants:**
- No arbitrary shell passthrough — every tool is whitelisted in the registry
- No implicit execution — `ExecutionPolicy` gates every action
- AI cannot override the safety layer — routing is done by pure regex, not by the LLM
- All findings data remains local — no telemetry, no external calls

---

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for the full guide.

**Quick contribution checklist:**
1. Fork the repository and create a feature branch
2. Write tests for all new behaviour — keep the suite at 100%
3. Run the full linting suite before opening a PR:

```bash
ruff check hydrasight/ tests/
ruff format --check hydrasight/ tests/
pylint hydrasight/ --fail-under=9.0
mypy hydrasight/ --ignore-missing-imports
python -m pytest tests/ -q -p no:ethereum
```

4. Open a pull request against `main` with a clear description of the change

Please review the [Code of Conduct](./CODE_OF_CONDUCT.md) and [Security Policy](./SECURITY.md) before contributing.

---

## License

MIT License — Copyright © 2026 Shyam. See [LICENSE](./LICENSE) for details.

---

<div align="center">

**Built with Python, Rich, Ollama, and a healthy respect for authorization boundaries.**

*If HydraSight helped you in a CTF or authorized engagement, consider giving it a ⭐*

</div>
