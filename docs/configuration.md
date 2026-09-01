# Configuration

HydraSight merges configuration from four sources, highest priority first:

1. Environment variables (`HYDRA_*`)
2. A `.env` file (if `python-dotenv` is installed)
3. A `hydrasight.json` file
4. Built-in defaults (`config/defaults.py`)

Unknown keys in `hydrasight.json` are rejected/ignored by the schema allow-list.

## Key settings

| Key | Default | Purpose |
| --- | --- | --- |
| `ollama_url` | `http://localhost:11434` | Ollama API endpoint |
| `kali_api_url` | `http://127.0.0.1:5000` | Kali MCP REST bridge |
| `model` | `qcwind/qwen3-8b-instruct-Q4-K-M:latest` | Orchestration model tag |
| `context_size` | `8192` | Context window |
| `output_dir` | `hydrasight_output` | Where reports, sessions and the audit log live |
| `execution_mode` | `confirm` | `confirm` \| `auto` \| `never` |
| `operator` | `operator` | Identity stamped on audit records |
| `wordlist` | `/usr/share/wordlists/dirb/common.txt` | Web content wordlist |
| `rockyou_path` | `/usr/share/wordlists/rockyou.txt` | Hash-cracking wordlist |
| `deep_scan_range` | `1-65535` | Port range for `scan` |
| `auto_save` / `auto_pdf` | `true` | Auto-write JSON/PDF after autopwn |

## Environment overrides

`HYDRA_OLLAMA_URL`, `HYDRA_KALI_URL`, `HYDRA_MODEL`, `HYDRA_VERBOSITY`,
`HYDRA_LPORT`, `HYDRA_OUTPUT_DIR`, and `HYDRA_LOG_FILE` are honored.

## Example

See [`hydrasight.json.example`](https://github.com/Shyamprasanth04/hydrasight/blob/main/hydrasight.json.example)
and the pre-signed authorization template
[`hydrasight.authorization.json.example`](https://github.com/Shyamprasanth04/hydrasight/blob/main/hydrasight.authorization.json.example).
