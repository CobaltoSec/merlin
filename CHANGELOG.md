# Changelog

All notable changes to Merlin are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-05-16

Hygiene patch — defaults only. No behavior change for existing users.

### Changed
- `merlin.generators.ollama.DEFAULT_OLLAMA_HOST`: `http://192.168.0.20:11434` → `http://127.0.0.1:11434` (matches upstream Ollama default; was previously a development LAN IP).
- `labs/vulnerable_chat.py`: same default change for `OLLAMA_HOST`.
- `labs/README.md`: example commands now reference `127.0.0.1`.
- `DESIGN.md`: three references to internal infra naming replaced with generic "local Ollama instance".

### Why
The previous default leaked an internal LAN IP and an infra-specific identifier into a public artifact. No real exposure (RFC1918 + a private name), but uglier than necessary for an open-source release.

## [0.1.0] — 2026-05-16

First public release. OWASP LLM01 (Prompt Injection) coverage end-to-end,
bundled vulnerable lab, Markdown reporting.

### Added — core
- `merlin.core.models` — pydantic v2 models: `Finding`, `EngagementState`,
  `PayloadSpec`, `BaselineSnapshot`, `SuccessVerdict`.
- `merlin.core.http_client` — `AsyncTargetClient` over `httpx.AsyncClient` with
  3-attempt retry, 429 Retry-After honored, exponential backoff on 5xx,
  configurable body template + JSON dot-path response extraction.
- `merlin.core.fingerprint` — neutral + refusal-bait probes capturing baseline
  latency, response shape, and refusal phrases.
- `merlin.core.success_detector` — heuristic verdict combining four signal
  classes: payload-specific substring matches, canary leak, length deviation,
  refusal absence.
- `merlin.core.session` — atomic `engagement.json` persistence; incremental
  writes per finding, crash-safe across the scan.

### Added — modules + generators
- `merlin.modules.base.Module` — abstract base for OWASP LLM Top 10 modules.
- `merlin.modules.prompt_injection.PromptInjectionModule` — LLM01 orchestrator:
  fingerprint → semaphore-gated payload dispatch (concurrency + jitter) →
  detect → append findings.
- `merlin.generators.base.Generator` — Protocol for payload sources.
- `merlin.generators.static.StaticGenerator` — loads curated YAML payloads.
- `merlin.generators.ollama.OllamaGenerator` — interface stub, raises
  `NotImplementedError` (lands in v0.2).

### Added — payload library
- 30 curated LLM01 payloads across 5 vectors (6 each): `override`, `role_play`,
  `encoding`, `delimiter_escape`, `indirect_context`. File:
  `merlin/payloads/data/llm01_prompt_injection.yaml`. Loader at
  `merlin/payloads/loader.py`.

### Added — reporting
- `merlin.reporting.report` + Jinja2 template `report.md.j2` — 5-section
  Markdown report: header / fingerprint / executive summary / findings table /
  detail blocks (payload + response excerpt + signals + repro curl).
- `strict_undefined` Jinja2 mode to fail loudly on missing context.

### Added — CLI
- `merlin scan` — run a module against a target. Flags: `--target`,
  `--module`, `--gen`, `--concurrency`, `--rate-limit`, `--output-dir`,
  `--canary`, `--fail-on-findings`, `--body-template`, `--response-path`,
  `--payload-placeholder`, `--method`, `--headers`, `--timeout`.
- `merlin report` — re-render `report.md` from a stored `engagement.json`.
- `merlin version` — print package version.
- Rich progress bar with per-payload HIT events.

### Added — lab target
- `labs/vulnerable_chat.py` — Flask app on `:5050`, `POST /api/chat`, two modes
  via `MERLIN_LAB_MODE`:
  - `mock` (default) — deterministic substring router, zero network deps.
  - `ollama` — proxy to a local Ollama instance with a vulnerable system prompt
    that hardcodes the canary `COBALT_LAB_2026`.
- `labs/README.md` + `labs/requirements.txt`.

### Added — testing + tooling
- `pyproject.toml` with editable install (`merlin = merlin.cli:app` console
  script), pytest config, ruff lint config.
- `requirements-dev.txt` (pytest, pytest-asyncio, respx, ruff).
- 37 tests across `tests/test_{models,payload_loader,http_client,success_detector,session,cli_smoke,smoke}.py`
  using subprocess + tempfile fixtures (no conftest), `respx` for HTTP mocking.
- `.github/workflows/test.yml` runs lint + pytest on Python 3.11 and 3.12.

### Added — docs
- `docs/QUICKSTART.md` — install, lab, first scan.
- `docs/PAYLOADS.md` — taxonomy of the v0.1 library, schema, severity policy,
  how to add payloads.
- `README.md` quickstart, capability matrix, OWASP coverage table, real-target
  example with custom body template + dot-path response extraction.

### Architecture notes
- HTTP is async (`httpx.AsyncClient`) gated by `asyncio.Semaphore(concurrency)`
  with per-request jitter — 30 payloads run in seconds.
- Severity is declared in YAML (author intent) and may be downgraded post-hoc
  by the module when detector confidence is `< 0.5`. No upgrades.
- Single baseline captured at scan start (in `EngagementState.fingerprint`);
  re-baseline is not done per payload (Cost/value tradeoff for v0.1).

### Known limitations
- Detector is calibrated on the bundled mock lab; real-target accuracy
  improves in v0.2 with the adversarial generator.
- Only LLM01 covered. LLM02 / LLM06 / LLM07 land in v0.2; LLM05 / LLM08 in v0.3.
- Ollama generator is stub-only (`NotImplementedError`).

## [Unreleased]

(see DESIGN.md for the v0.2 plan)
