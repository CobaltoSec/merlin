![CI](https://github.com/CobaltoSec/merlin/actions/workflows/test.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)

# Merlin — LLM Attack Surface Framework

> The Nikto for OWASP LLM Top 10. Systematic offensive testing for AI features in modern web applications.

> **Legal**: This tool is for authorized security testing and research only. Use against LLM-integrated applications you do not own or lack explicit written permission to test is illegal. Authors assume no liability for misuse. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## v0.1.0 — what's in the box

| Capability | Status |
|------------|--------|
| OWASP LLM01 (Prompt Injection) — 30 curated payloads | ✅ |
| Async HTTP client (httpx) with retry / 429 / timeout | ✅ |
| Heuristic success detector (signal + canary + length + refusal) | ✅ |
| Markdown report (jinja2, 5 sections incl. repro curl) | ✅ |
| Vulnerable lab target (Flask, dual-mode mock / ollama) | ✅ |
| Static payload generator | ✅ |
| Ollama / Claude generators | 🚧 v0.2 |
| OWASP LLM02, LLM05–LLM08 | 🚧 v0.2 / v0.3 |

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
| LLM01 | Prompt Injection                  | ✅ v0.1 (30 payloads, 5 vectors) |
| LLM02 | Sensitive Information Disclosure  | 🚧 v0.2 |
| LLM05 | Improper Output Handling          | 🚧 v0.3 |
| LLM06 | Excessive Agency                  | 🚧 v0.2 |
| LLM07 | System Prompt Leakage             | 🚧 v0.2 |
| LLM08 | Vector / Embedding Weaknesses     | 🚧 v0.3 |

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
