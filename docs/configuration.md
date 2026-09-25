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

The bridge URL must be the address **HydraSight can reach**, not the address the
bridge binds to. When `kali-server-mcp` runs on a separate Kali box, start it
listening on all interfaces (`kali-server-mcp --ip 0.0.0.0`) and point
`kali_api_url` at that host, e.g.:

```bash
export HYDRA_KALI_URL="http://192.168.100.10:5000"   # or set it in hydrasight.json
```

Verify the bridge before starting an engagement:

```bash
curl -s http://192.168.100.10:5000/health
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"command":"whoami"}' http://192.168.100.10:5000/api/command
```

If the second call 404s, the bridge on that port does not expose a command API
— HydraSight's `status` line reports exactly which routes were probed.
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
