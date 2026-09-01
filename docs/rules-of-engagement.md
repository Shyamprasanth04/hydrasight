# Rules of Engagement

The Rules of Engagement (ROE) define the safety envelope for an engagement.
They live in `hydrasight.roe.json`; if absent, a permissive default is used
(wildcard scope, no approval gates, two-hour runtime limit).

## Fields

| Field | Meaning |
| --- | --- |
| `allowed_targets` | List of IPs / CIDRs, or `["*"]` for wildcard |
| `blocked_ports` | Ports that must never be touched |
| `blocked_modules` | Substring-matched module names that are blocked |
| `require_approval_for` | Phases (e.g. `EXPLOIT`, `POST_EXPLOIT`) requiring approval |
| `max_runtime_minutes` | Engagement runtime cap (default 120) |
| `max_threads` | Concurrency limit |
| `kill_switch` | When `true`, **all dispatch stops immediately** |

## ROE ∩ authorization

The effective scope is the **intersection** of the ROE `allowed_targets` and the
operator attestation scope:

- An attestation **cannot** widen the ROE. If ROE allows `10.0.0.0/8` and the
  operator attests `10.0.0.0/8` + `192.168.0.0/16`, a `192.168.x` target is still
  blocked by ROE.
- The ROE **cannot** widen the attestation. If ROE is wildcard but the operator
  only attested `10.0.0.0/8`, a `192.168.x` target is denied by authorization.
- The `kill_switch` overrides everything.

Use the `roe` REPL command to view the active envelope and its source file.

## Example

```json
{
  "allowed_targets": ["10.10.10.0/24"],
  "blocked_ports": [53],
  "blocked_modules": ["mimikatz"],
  "require_approval_for": ["EXPLOIT", "POST_EXPLOIT"],
  "max_runtime_minutes": 60,
  "kill_switch": false
}
```
