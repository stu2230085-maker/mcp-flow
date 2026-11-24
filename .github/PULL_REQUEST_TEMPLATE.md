## Summary
<!-- Describe what this PR implements or fixes and link the Issue -->
Closes #

## Files / Modules Touched
- `src/mcp_flow/...`
- `tests/...`

## Architectural Invariant Checklist (for Author Agent & Opus Reviewer)
- [ ] **Passive Observation Only**: No active scanning, payload injection, or traffic blocking added.
- [ ] **Zero Core Dependencies**: `src/mcp_flow/` uses Python 3.10+ standard library only.
- [ ] **Zero-Mutation Relay**: Proxy does not alter relayed JSON-RPC payloads or block on logging failures.
- [ ] **Recomputable Derived Data**: `messages` remains append-only; `calls` / `fragments` / `flows` can be regenerated via `mcp-flow analyze`.
- [ ] **Epistemic Disclaimer**: Output preserves the note that edges represent content correlation, not proof of causal LLM reasoning.
- [ ] **Privacy & Permissions**: SQLite DB enforces `0600` permissions; Read-only MCP server withholds raw fragment text by default (`expose_text=False`).
- [ ] **Schema Migration**: If DB schema changed, a new migration version was appended to `MIGRATIONS` in `src/mcp_flow/store/db.py`.

## Verification & Benchmark Output
Paste the output of `PYTHONPATH=src:. python3 -m mcp_flow evaluate`:

```text
```
