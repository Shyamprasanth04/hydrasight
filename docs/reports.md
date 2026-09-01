# Reports

HydraSight produces structured engagement output in the configured
`output_dir` (default `hydrasight_output/`).

## JSON export

`save <path>` (or auto-save after `autopwn`) writes a JSON document containing
the normalized `ReportModel` plus a legacy-compatible raw findings payload:

```python
from hydrasight.reporting.json_reporter import save_json
ok = save_json(findings, "engagement.json")
```

Saves fail safely — filesystem errors, invalid paths (e.g. embedded null
bytes), and unserializable objects return `False` rather than raising.

## PDF report

`report <ip>` (or auto-PDF after `autopwn`) renders a PDF via ReportLab:

```python
from hydrasight.reporting.pdf_reporter import generate_pdf
generate_pdf("10.10.10.15", findings, "engagement.pdf")
```

## Engagement outcome

`conclusion` classifies the engagement using a fixed priority order
(`reporting/outcome.py`):

`POST_ACCESS` → `CREDENTIAL_LED` → `EXPLOIT_CONFIRMED` → `VALIDATION` →
`VULN_CANDIDATES` → `RECON_ONLY` → `NO_FINDINGS`.

## Examples

The `examples/` directory contains a synthetic lab engagement generated
through the real reporters:

- `examples/sample-engagement.json`
- `examples/sample-engagement.pdf`

Use these as references for the report schema and layout.
