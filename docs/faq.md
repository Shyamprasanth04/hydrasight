# FAQ

**Do I have to authorize every time?**
Yes — HydraSight is deny by default. Use the `authorize <ip|cidr>` REPL command
for interactive work, or drop a `hydrasight.authorization.json` file in the
working directory for CI/CTF runs (auto-loaded at startup).

**What happens if I target an IP outside my attested scope?**
The command is blocked at the `Dispatcher` chokepoint, a `[BLOCKED]` message is
returned, and a `command_blocked` record is written to the audit log. Nothing
reaches Kali.

**What's the difference between ROE and authorization?**
ROE (`hydrasight.roe.json`) is the engagement envelope; authorization is the
operator's attestation. The effective scope is their **intersection** — neither
can widen the other. The ROE kill-switch blocks everything.

**Can I tamper with the audit log?**
The log is hash-chained. `AuditLogger.verify()` replays the chain and detects
altered lines (hash mismatch) and deleted lines (broken `prev_hash` link).

**Does plain English ever run a tool?**
No. Conversational input (`/ask` or bare text) is routed to the chat model and
never dispatches. Only explicit `/run` actions, confirmed plans, and builtins
(`scan`/`autopwn`) dispatch — and only after the scope gate passes.

**Where are secrets handled?**
Secrets in commands (e.g. `sshpass -p`, URL credentials, `password=`) are
redacted to `[REDACTED]` before being written to the audit log.

**Does the Docker image contain attack tools?**
No. The image runs as a non-root user and contains only the orchestrator; all
offensive execution happens against the separate Kali bridge service.

**Which Python versions are supported?**
Python 3.10, 3.11, and 3.12, all tested in CI.

**`status` says `kali api offline` — the bridge is definitely running.**
Check the URL, not the process. HydraSight probes `kali_api_url` (default
`http://127.0.0.1:5000`); a bridge running on another machine — your Kali VM or
box — is not reachable at that address. Start it with
`kali-server-mcp --ip 0.0.0.0` and point HydraSight at it:

```bash
export HYDRA_KALI_URL="http://<kali-ip>:5000"
```

If the message instead reads `no kali-server-mcp API at <url> (404 on …)`, then
something *is* answering on that port but it is not a kali-server-mcp bridge —
another service grabbed port 5000, or a stray `HTTP_PROXY`/`HTTPS_PROXY` is
routing the request through a proxy that 404s it. `curl` the same URL from the
same shell to compare.
