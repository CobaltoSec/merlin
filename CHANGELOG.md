# Changelog

All notable changes to Merlin are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-05-17

Patch release — new signal source `refusal_mentions_keyword` to reduce the FP class
where a model refuses but echoes payload keywords, triggering a false `signal:*:direct`.
Documented and confirmed in cs01 Run A (qwen2.5:14b, 2 of 3 known FPs reclassified).
Tests: 81 → 85.

### Added
- **`refusal_mentions_keyword` signal source**: when the overall response contains a
  refusal phrase (from `REFUSAL_PHRASES`) and the matched signal appeared as `direct`,
  the source is reclassified to `refusal_mentions_keyword` and confidence multiplied
  by `REFUSAL_KEYWORD_MULTIPLIER = 0.2`. This is a stricter downgrade than the
  lexical ×0.3 — refusal echoes are noisier.
- `REFUSAL_KEYWORD_MULTIPLIER = 0.2` constant in `success_detector.py`.
- `scripts/reclassify-findings.py` — standalone script to retroactively re-run
  `detect_success()` over existing `engagement.json` files without re-prompting
  the model. Useful for comparative analysis across detector versions.
- `tests/fixtures/cs01_run_a_fps.json` — machine-readable documentation of the
  3 confirmed FPs and 1 TP from cs01 Run A, with expected v0.2.1 outcomes.
- 4 new tests in `tests/test_success_detector.py`: dampen FP, regression test
  for Run A qwen14b, anti-regression TP guard, refusal-without-keyword guard.

### Notes
- The third known FP from cs01 Run A (`security_audit_pretext`, "I don't have
  direct access to...") is NOT caught by this heuristic — the phrase "i don't have"
  is not in `REFUSAL_PHRASES`. This validates the roadmap item for v0.3
  LLM-judge detector. Adding "i don't" broadly to `REFUSAL_PHRASES` risks false
  reclassification of compliant responses.

## [0.2.0] — 2026-05-16

Major release — detector v0.2, real Ollama generator, three new OWASP LLM Top 10
categories. Coverage triples (LLM01 only → LLM01+LLM07+LLM02+LLM06). Test count
doubles (37 → 81).

### Added — coverage
- **LLM07 — System Prompt Leakage** module + 22 payloads across 5 vectors
  (`direct_ask`, `role_inversion`, `metadata_exfil`, `instruction_repeat`,
  `delimiter_break`). CLI: `merlin scan --module system-prompt-leak`.
- **LLM02 — Sensitive Information Disclosure** module + 18 payloads across 4
  vectors (`pii_extraction`, `training_data_recall`, `api_key_probe`,
  `internal_url_probe`). CLI: `merlin scan --module sensitive-info-disclosure`.
- **LLM06 — Excessive Agency** module + 16 payloads across 4 vectors
  (`ssrf_via_tool`, `command_injection_via_tool`, `file_read_via_tool`,
  `tool_chain_abuse`). CLI: `merlin scan --module excessive-agency`.
- `merlin.core.mock_tool_server.MockToolServer` — companion lab tool for LLM06
  probing. Three pseudo-dangerous endpoints (`http_fetch`, `file_read`,
  `shell_exec`) each respond with a unique canary
  (`CANARY_HTTP_FETCH_HIT_M3RL1N`, etc.) so canaries propagate end-to-end when
  the target LLM relays the mock tool's response.

### Changed — core
- **`merlin.core.success_detector` v0.2**: signal-source classification.
  Each signal occurrence is classified as `direct`, `lexical_codeblock`,
  `lexical_framing`, `canary`, `length_deviation`, or `refusal_absence`. When
  the majority of `signal:*` matches fall inside fenced code blocks or after
  illustrative framing phrases ("for example:", "imagine if...", "por
  ejemplo"), confidence is multiplied by 0.3. Direct driver: the smoke Run 2
  (llama3.2:3b) flagged `fake_new_system_directive` as a hit because the model
  echoed signals inside a generated code block. The regression test
  `test_lexical_framing_repro_run2_fake_new_system_directive` locks it in.
- **Encoded signal format** gains a third part: `signal:<text>:<source>`.
  Backward-compatible: `s.startswith("signal:foo")` still matches.
- **`SuccessVerdict`** gains a structured `signal_sources: tuple[tuple[str, str], ...]`
  field with empty default — backward-compatible for v0.1 callers.
- **`Module.run()` signature**: receives a pre-built `payloads: list[PayloadSpec]`
  instead of a `Generator` instance. Fixes a latent v0.1 bug where
  `generator.generate()` was called twice (CLI for progress bar + module). Saves
  2× cost on Ollama generation.
- **`SingleShotModule`**: shared base for LLM01/LLM02/LLM07. Subclasses are 5
  lines (declare `owasp_id` / `category` / `name`).

### Added — generators
- **`merlin.generators.ollama.OllamaGenerator`** — actual implementation (was a
  `NotImplementedError` stub in v0.1). POSTs each seed to
  `{host}/api/generate`, asks for N reworded variants, validates each against
  `PayloadSpec`. Tolerates `‏```json` fences, prose around the array, missing
  fields, network errors — never crashes the scan. Inherits `severity` /
  `vector` from the seed; variant IDs are `{seed.id}__ollama_v{idx}`.

### Added — CLI
- `--ollama-host`, `--ollama-model`, `--variants-per-seed` — Ollama generator
  configuration.
- `--max-payloads N` — cap the total payload count per scan after generation.
  Useful for paid-API targets (OpenAI / Anthropic) or small Ollama models where
  token cost matters.

### Added — reporting
- New **Signal Source** column in the report's Findings Table, summarizing each
  finding's signal classifications (`direct(2) lexical(1)` style). Exposed via
  the `signal_source_summary()` helper in the Jinja context.

### Added — tests
- `tests/test_ollama_generator.py` — 11 tests with `respx` mocking.
- `tests/test_modules_singleshot.py` — 5 tests across LLM01/02/07 modules.
- `tests/test_mock_tool_server.py` — 8 tests for `MockToolServer`.
- `tests/test_excessive_agency_module.py` — 4 tests covering canary echo
  detection and capability-limited targets.
- `tests/test_success_detector.py` — 11 new tests, including the
  Run 2 regression test.
- `tests/test_payload_loader.py` — 5 new tests covering the three new
  categories.
- Coverage total: 37 (v0.1) → 81 (v0.2), all green.

### Known limitations
- **LLM06** requires target configuration: the operator points the target's
  tool array at `MockToolServer.aiohttp_app()` for full validation. Targets
  without configurable tool calling degrade to "model describes the tool
  invocation" matching, much weaker. Documented in
  `merlin/modules/excessive_agency.py` docstring.
- Detector v0.2 still heuristic. v0.3 plan: replace with LLM-judge.
- PyPI publish deferred to v0.3 (pending 2-3 real-target case studies).

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
