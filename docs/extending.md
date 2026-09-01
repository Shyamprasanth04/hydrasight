# Extending HydraSight

## Adding a new tool / action

1. Register a command spec in the action registry (`core/registry.py` +
   `core/builtin_actions.py`) with a typed builder in `core/command_builder.py`.
2. Provide a render path in `Dispatcher._render` if the command is produced
   internally.
3. Map a display label in `TOOL_LABELS` (`config/defaults.py`).
4. Route natural-language phrasing in `services/intent_router.py` if the tool
   should be reachable from `/run`.
5. Add tests in `tests/`.

All new actions automatically inherit command sanitization, the ROE ∩
authorization gate, and audit logging because they pass through the
`Dispatcher` chokepoint.

## Adding a post-access handler

Implement the `BasePostAccessHandler` interface in
`services/post_access/base.py` and register it through the
`PostAccessHandler` factory (`factory.py`). Re-export any new public names from
`services/post_access/__init__.py` so the stable import path keeps working.

## Custom LLM options

Per-call Ollama options are configurable via `ollama_options_orchestrator` and
`ollama_options_chat` in `hydrasight.json` (nested keys are merged, not
replaced).

## Reporting extensions

- Add report fields via the `ReportModel` (`models/report_model.py`).
- Outcome classification lives in `reporting/outcome.py` — add new outcomes
  there rather than in the renderer.

> Public API stability: REPL commands and configuration keys are public and
> must remain backward-compatible. Internal module refactors are welcome.
