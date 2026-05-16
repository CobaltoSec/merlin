![CI](https://github.com/CobaltoSec/merlin/actions/workflows/test.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# Merlin — LLM Attack Surface Framework

> The Nikto for OWASP LLM Top 10. Systematic offensive testing for AI features in modern web applications.

> **Legal**: This tool is for authorized security testing and research only. Use against LLM-integrated applications you do not own or lack explicit written permission to test is illegal. Authors assume no liability for misuse. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Status

**v0.1.0-pre** — design phase. The architecture and scope are frozen
(see [DESIGN.md](DESIGN.md)). Implementation has not started; this
repository is a scaffold for v0.1 work.

## Why

OWASP LLM Top 10 has named the attack surface since 2023, but the
practitioner toolchain has not caught up. Garak and PyRIT exist, but
they are academic/research-grade. Red teamers attacking real
LLM-integrated applications during engagements are still hand-rolling
payloads case by case.

Merlin closes that gap. It is to LLM features what Nikto is to web
servers: a fast, opinionated, scriptable scanner that turns OWASP LLM
Top 10 into a 30-minute first pass.

## Architecture — 4 Layers

Same blueprint as [Kestrel](https://github.com/CobaltoSec/kestrel):

```
┌─────────────────────────────────────────────────────────┐
│  4. MEMORY                                              │
│     engagement state · findings · report rendering      │
├─────────────────────────────────────────────────────────┤
│  3. EXECUTION                                           │
│     HTTP client · success detection heuristics          │
├─────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION                                       │
│     module dispatch · payload selection · chain logic   │
├─────────────────────────────────────────────────────────┤
│  1. INTEL                                               │
│     fingerprint (model, capabilities, prompt clues)     │
└─────────────────────────────────────────────────────────┘
```

See [DESIGN.md](DESIGN.md) for the full architectural breakdown.

## OWASP LLM Top 10 Coverage (planned)

| ID    | Category                          | Target version |
|-------|-----------------------------------|----------------|
| LLM01 | Prompt Injection                  | v0.1           |
| LLM02 | Sensitive Information Disclosure  | v0.2           |
| LLM05 | Improper Output Handling          | v0.3           |
| LLM06 | Excessive Agency                  | v0.2           |
| LLM07 | System Prompt Leakage             | v0.2           |
| LLM08 | Vector / Embedding Weaknesses     | v0.3           |

## Quickstart (planned API — not yet implemented)

```bash
merlin scan --target https://example.com/api/chat
merlin scan --target https://example.com/api/chat --gen ollama
merlin scan --target https://example.com/api/chat --gen claude
```

## Contributing

Issues and PRs welcome once v0.1 lands. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Related projects

- [Kestrel](https://github.com/CobaltoSec/kestrel) — HTB engagement framework, same 4-layer architecture
- [CobaltoSec](https://cobalto-sec.tech) — parent organization
