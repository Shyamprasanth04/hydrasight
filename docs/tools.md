# Tools

HydraSight orchestrates standard Kali tooling through the `kali-server-mcp`
REST bridge. Tools are modeled as typed command specs rendered by the
`CommandBuilder` and validated by the command sanitizer before execution.

## Supported actions

| Action id | Label | Underlying tooling |
| --- | --- | --- |
| `nmap_scan` | nmap | `nmap` host/service discovery & NSE scripts |
| `gobuster_scan` | gobuster | `gobuster` web content/directory discovery |
| `nikto_scan` | nikto | `nikto` web vulnerability scan |
| `whatweb_scan` | whatweb | `whatweb` web fingerprinting |
| `smb_enum` | enum4linux | `enum4linux` SMB enumeration |
| `ssh_brute` | hydra-ssh | `hydra` SSH credential testing |
| `ftp_brute` | hydra-ftp | `hydra` FTP credential testing |
| `post_exploit` | msfconsole | Metasploit resource scripts (post-exploitation) |
| `run_command` | shell | Arbitrary sanitized shell command |

Tool-specific timeouts are defined in `config/defaults.py` (`TOOL_TIMEOUTS`)
and scaled by the active engagement profile.

## Tool chaining & verification

- Findings are parsed from tool output into typed `FindingRecord`s.
- The `VerifierService` re-runs focused commands to confirm findings, with
  per-finding isolation so one failure cannot abort verification.
- Credential recovery (`john`) is handled by the hash-cracking module.

> The Docker image ships **no offensive tools** — all execution happens against
> the Kali bridge, keeping the orchestrator environment safe to run anywhere.
