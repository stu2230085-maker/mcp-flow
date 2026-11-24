# Contributing & Multi-Agent Workflow (`mcp-flow`)

`mcp-flow` uses a structured **Issue -> Branch -> Pull Request -> Automated CI -> AI/Human Review -> Squash Merge** workflow so multiple AI coding agents (**Codex Cloud**, **Claude Opus / Claude Code**, **GitHub Copilot SWE Agent**, **Google Jules**, **Antigravity**) and human developers can collaborate cleanly without stepping on each other's changes.

---

## 1. Roles in the Multi-Agent Workflow

| Role | Typical Agent / Actor | Responsibility |
| :--- | :--- | :--- |
| **Implementer** | Codex Cloud (`openai-code-agent`), Copilot (`copilot-swe-agent`), Claude (`anthropic-code-agent`), Jules, or Local Agent | Picks up a GitHub Issue, creates a topic branch, implements the feature/fix with unit tests, runs `mcp-flow evaluate`, and opens a Pull Request against `main`. |
| **Reviewer / Architect** | Claude Opus (in dedicated review chat) or Human Maintainer | Audits the PR diff against the 7 architectural invariants in [CLAUDE.md](CLAUDE.md), verifies evaluation metrics (`NegFP == 0`), requests changes if needed, or approves and squash-merges. |
| **Automated Gate** | GitHub Actions CI (`.github/workflows/ci.yml`) | Runs unit tests and synthetic evaluation across Python 3.10–3.13 on every push and PR. |

---

## 2. Step-by-Step Git & PR Lifecycle

### Step 1: Pick or Create an Issue
Every unit of work should correspond to a GitHub Issue using the [Agent Task template](.github/ISSUE_TEMPLATE/agent_task.md). Each Issue specifies:
- Goal & Design Reference
- Target files/modules to touch (to prevent merge conflicts with parallel tasks)
- Acceptance criteria & test commands

### Step 2: Create a Dedicated Topic Branch
Never commit directly to `main`. Create a descriptive branch from `origin/main`:

```bash
git fetch origin
git checkout -b feat/<issue-number>-<short-description> origin/main
```

Branch prefixes:
- `feat/` — New capabilities (e.g., `feat/1-wrap-config`)
- `fix/` — Bug fixes or false-positive tuning
- `eval/` — Synthetic benchmark scenarios & evaluation tools
- `docs/` — Documentation & architecture diagrams
- `perf/` — Throughput, indexing, and SQLite performance optimizations

### Step 3: Implement & Run Local Quality Gates
Follow the coding conventions in [AGENTS.md](AGENTS.md):
- Standard library only in `src/mcp_flow/`
- Type annotations (`from __future__ import annotations`) on all functions
- New tests in `tests/test_*.py` using `unittest.TestCase` (compatible with both `unittest` and `pytest`)

Verify locally:
```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
PYTHONPATH=src:. python3 -m mcp_flow evaluate
```

### Step 4: Commit & Open a Pull Request
Use Conventional Commits:
- `feat(<scope>): <summary> (#<issue>)`
- `fix(<scope>): <summary> (#<issue>)`
- `test(<scope>): <summary> (#<issue>)`

Push your branch and open a PR using the PR template:
```bash
git push -u origin feat/<issue-number>-<short-description>
gh pr create --fill
```

### Step 5: Opus Review & Squash Merge
In the review session (e.g., Claude Opus chat):
1. Opus inspects `gh pr diff <PR_NUMBER>` and CI results.
2. Opus checks all 7 invariants in [CLAUDE.md](CLAUDE.md).
3. Once approved, the PR is **Squash Merged** into `main` and the topic branch is deleted to keep commit history linear and clean.
