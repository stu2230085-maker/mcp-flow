---
name: AI Agent Task
about: Self-contained implementation task for Codex Cloud, Claude, Copilot, or Jules
title: "feat: "
labels: ["agent-task"]
---

## Background & Goal
<!-- Explain what problem this task solves and how it fits into docs/design.md -->

## Scope & Target Files
<!-- List exact files to create or modify so parallel agents do not conflict -->
- `[MODIFY]` `src/mcp_flow/...`
- `[NEW]` `tests/test_...`

## Detailed Requirements
1. 
2. 
3. 

## Acceptance Criteria & Verification
- [ ] Adheres to all principles in `AGENTS.md` and `CLAUDE.md` (zero core dependencies, passive observation, `0600` DB permissions).
- [ ] Unit tests added and passing via `PYTHONPATH=src:. python3 -m unittest discover -s tests -v`.
- [ ] Synthetic benchmark passes with `NegFP == 0` via `PYTHONPATH=src:. python3 -m mcp_flow evaluate`.
