[![PyPI version](https://img.shields.io/pypi/v/cobaltosec-merlin.svg)](https://pypi.org/project/cobaltosec-merlin/)
[![PyPI downloads](https://img.shields.io/pypi/dm/cobaltosec-merlin.svg)](https://pypi.org/project/cobaltosec-merlin/)
[![CI](https://github.com/CobaltoSec/merlin/actions/workflows/test.yml/badge.svg)](https://github.com/CobaltoSec/merlin/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)
<!-- MERLIN_TESTS_START -->[![Tests](https://img.shields.io/badge/tests-0%20passing-brightgreen.svg)](tests/)<!-- MERLIN_TESTS_END -->

# Merlin — LLM Attack Surface Framework

> The Nikto for OWASP LLM Top 10. Systematic offensive testing for AI features in modern web applications.

> **Legal**: This tool is for authorized security testing and research only. Use against LLM-integrated applications you do not own or lack explicit written permission to test is illegal. Authors assume no liability for misuse. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Install

```bash
pip install cobaltosec-merlin
merlin version
```

## v0.3.0 — what's in the box

| Capability | Status |
|------------|--------|
| OWASP LLM01 (Prompt Injection) — 30 payloads, 5 vectors | ✅ |
| OWASP LLM07 (System Prompt Leakage) — 22 payloads, 5 vectors | ✅ |
| OWASP LLM02 (Sensitive Info Disclosure) — 18 payloads, 4 vectors | ✅ |
| OWASP LLM06 (Excessive Agency) — 16 payloads + MockToolServer | ✅ |
| Detector v0.2.1 — signal source classification (direct / lexical / refusal_kw / canary) | ✅ |
| Ollama generator (contextual variant generation via LLM) | ✅ |
| Async HTTP client (httpx) with retry / 429 / timeout | ✅ |
| Markdown report (jinja2, signal type column) | ✅ |
| Vulnerable lab target (Flask, dual-mode mock / ollama) | ✅ |
| 85 tests | ✅ |

## Quick start

```bash
git clone https://github.com/CobaltoSec/merlin && cd merlin
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e .
pip install -r labs/requirements.txt

# Terminal A — start the bundled lab (mock mode, deterministic, no network)
python labs/vulnerable_chat.py

# Terminal B — scan it
merlin scan --target http://127.0.0.1:5050/api/chat --output-dir ./engagements
```

You should see a colored summary table plus two artifacts under `engagements/`:

```
engagements/127_0_0_1_5050_api_chat_<ts>/
├── engagement.json    # canonical state (incrementally written)
└── report.md          # human-readable Markdown report
```

## What Merlin does, in one sentence

It sends curated prompt-injection payloads at any HTTP endpoint that fronts an
LLM, classifies the responses with a heuristic detector, and writes a
reproducible report — so a red-team operator gets from "is this LLM endpoint
attackable?" to a list of confirmed findings in under a minute.

## Architecture — 4 Layers

Same blueprint as [Kestrel](https://github.com/CobaltoSec/kestrel):

```
┌─────────────────────────────────────────────────────────┐
│  4. MEMORY      engagement state · findings · report    │
├─────────────────────────────────────────────────────────┤
│  3. EXECUTION   HTTP client · success detection         │
├─────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION  module dispatch · payload selection  │
├─────────────────────────────────────────────────────────┤
│  1. INTEL       fingerprint · model + capability probes │
└─────────────────────────────────────────────────────────┘
```

See [DESIGN.md](DESIGN.md) for the full architectural breakdown.

## OWASP LLM Top 10 Coverage

| ID    | Category                          | Status |
|-------|-----------------------------------|--------|
| LLM01 | Prompt Injection                  | ✅ v0.1 — 30 payloads, 5 vectors |
| LLM02 | Sensitive Information Disclosure  | ✅ v0.2 — 18 payloads, 4 vectors |
| LLM06 | Excessive Agency                  | ✅ v0.2 — 16 payloads + MockToolServer |
| LLM07 | System Prompt Leakage             | ✅ v0.2 — 22 payloads, 5 vectors |
| LLM05 | Improper Output Handling          | 🚧 v0.3 |
| LLM09 | Misinformation                    | 🚧 v0.3 |
| LLM10 | Unbounded Consumption             | 🚧 v0.3 |
| LLM03 | Supply Chain                      | 🔮 spin-off `merlin-supply-audit` |
| LLM04 | Data / Model Poisoning            | 🔮 v0.5+ |
| LLM08 | Vector / Embedding Weaknesses     | 🔮 v0.4 |

## Case Studies

Real-world benchmarks run with Merlin on authorized targets:

| # | Target | Models | Key finding |
|---|--------|--------|-------------|
| [CS-01](case-studies/01-ollama-bench/report.md) | Ollama local — qwen2.5 multimodel | 7B / 14B / 32B | 7B: 73% hit rate; 14B most resistant on LLM01; size ≠ safety alignment |

## CLI

```bash
merlin scan --target <url>            \
            --module prompt-injection \
            --gen static              \
            --concurrency 5           \
            --rate-limit 5            \
            --output-dir ./engagements

merlin report --engagement ./engagements/<dir>
merlin version
```

For non-default target shapes (e.g. OpenAI-style `messages` body):

```bash
merlin scan --target https://api.example.com/v1/chat/completions \
  --body-template '{"messages":[{"role":"user","content":"{payload}"}]}' \
  --response-path 'choices.0.message.content' \
  --headers 'Authorization: Bearer sk-...'
```

## Docs

- [QUICKSTART](docs/QUICKSTART.md) — install, lab, first scan
- [PAYLOADS](docs/PAYLOADS.md) — taxonomy of the v0.1 library + how to add yours
- [DESIGN](DESIGN.md) — architecture and roadmap
- [labs/](labs/) — bundled vulnerable target

## Limitations (honest)

- Detector is calibrated on the bundled lab. Real-target accuracy will improve
  in v0.2 with the contextual adversarial generator.
- Only LLM01 is covered in v0.1 — the rest of OWASP LLM Top 10 lands in v0.2 / v0.3.
- Severities declared in the payload library are intentional priors and can be
  downgraded post-hoc when the detector's confidence is low.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome on payloads, generators,
modules, and docs.

## License

MIT — see [LICENSE](LICENSE).

## Related projects

- [Kestrel](https://github.com/CobaltoSec/kestrel) — HTB engagement framework, same 4-layer architecture
- [CobaltoSec](https://cobalto-sec.tech) — parent organization
