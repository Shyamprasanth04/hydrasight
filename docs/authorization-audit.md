# Authorization & Audit

## Mandatory authorization

Nothing that touches a target executes until an operator attests
authorization for its scope. Scope is a list of **IP addresses and/or CIDR
networks**.

### Interactive (REPL)

```text
hydra·sight › authorize 10.10.10.0/24 192.168.56.10
about to authorize testing of scope: 10.10.10.0/24, 192.168.56.10
type 'I AUTHORIZE' exactly to confirm, anything else cancels.
attest › I AUTHORIZE
authorization granted for scope: 10.10.10.0/24, 192.168.56.10
```

- The phrase **`I AUTHORIZE`** must be typed exactly (case-sensitive).
- Running `authorize` with no argument prints the current scope.
- Once granted, the scope is **locked** for the session; run `clear` to reset.

### Unattended / CI / CTF

Place a pre-signed file named `hydrasight.authorization.json` in the working
directory; it is auto-loaded at startup (deny by default if malformed or
missing `phrase_confirmed`):

```json
{
  "operator": "ci-bot",
  "scope": ["10.10.10.0/24"],
  "reference": "engagement ticket #123",
  "phrase_confirmed": true,
  "expires_after_minutes": 480
}
```

Use the API directly for custom flows:

```python
from hydrasight.security.authorization import AuthorizationManager, ATTEST_PHRASE

auth = AuthorizationManager()
auth.record_interactive("alice", ["10.0.0.0/8"], ATTEST_PHRASE)
allowed, reason = auth.check("10.0.0.5")   # (True, "...")
allowed, reason = auth.check("8.8.8.8")    # (False, "target ... outside attested scope ...")
```

Attestations expire after `expires_after_minutes` (default 480; `0` = never).

## Tamper-evident audit trail

Every security event is appended to `<output_dir>/hydrasight_audit.jsonl` as a
hash-chained JSON record:

```text
sequence, ts, action, operator, tool, target, command (redacted),
decision, reason, roe_scope, authorization_id, session_id, extra,
prev_hash, hash
```

- `hash = sha256(prev_hash + canonical_json(payload))`.
- The chain **resumes** from the last line if the log already exists.
- Writes are fail-safe — an audit error never aborts an engagement.

Verify integrity at any time:

```python
from hydrasight.security.audit import AuditLogger

ok, message = AuditLogger("hydrasight_output").verify()
# ok == False if any line was tampered with or deleted.
```

Recorded actions include `command_allowed`, `command_blocked`,
`authorization_granted`, `authorization_denied`, `engagement_start`, and
`engagement_end`.
