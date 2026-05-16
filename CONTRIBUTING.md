# Contributing to Merlin

Merlin is an LLM attack surface framework maintained by CobaltoSec.
Contributions that improve OWASP LLM Top 10 coverage, success detection
accuracy, or operator experience are welcome.

## What we accept

### 1. New attack modules (`merlin/modules/`)
Each OWASP LLM Top 10 category lives in a dedicated module. To add or extend one:
1. Subclass the base module interface (see `merlin/core/`).
2. Add curated payloads to `merlin/payloads/data/<category>.yaml`.
3. Implement success detection heuristics in `merlin/core/success_detector.py`.
4. Add fixtures and tests under `tests/modules/`.

### 2. Payload library (`merlin/payloads/data/`)
YAML files curated per technique. Each entry needs:
- `id` — stable identifier
- `technique` — short description
- `payload` — the injection string
- `signals` — patterns to look for in response

**No targeted payloads** — no real-world target names, no brand-specific
jailbreaks against named products.

### 3. Generators (`merlin/generators/`)
- `static.py` — stdlib only, zero deps
- `ollama.py` — local LLM
- `claude.py` — Anthropic API

New generators must implement the `Generator` protocol.

### 4. Documentation
Improvements to `README.md`, `DESIGN.md`, and `docs/` welcome.

## PR review criteria

| Criterion              | How we check                                |
|------------------------|---------------------------------------------|
| Tests pass             | `pytest tests/ -v`                          |
| No hardcoded creds     | grep for `password\|token\|key\|sk-`        |
| No targeted payloads   | review for real-world target names          |
| Lint clean             | `ruff check merlin/ tests/`                 |

## Commit message conventions

```
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`  
Scopes: `cli`, `core`, `modules`, `payloads`, `generators`, `reporting`, `docs`

Examples:
```
feat(modules): add LLM07 system prompt leak module
fix(success-detector): handle empty response body
docs(readme): update OWASP coverage table
```

Subject: imperative mood, ≤72 chars, no trailing period.

## Local setup

```bash
python3 --version    # 3.11+
python3 -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
pytest tests/ -v
```

Never commit `.env`, API keys, or session state files.
