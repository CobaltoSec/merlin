# Merlin Quickstart

5 minutes from clone to first report.

## Prerequisites

- Python 3.11 or 3.12
- `git`
- A target LLM endpoint (or use the bundled lab — covered below)

## 1. Install

```bash
git clone https://github.com/CobaltoSec/merlin
cd merlin
python -m venv .venv
. .venv/bin/activate                          # Windows: .venv\Scripts\Activate.ps1
pip install -e .
```

The `merlin` console command is now on your PATH inside the venv.

```bash
merlin version
# → merlin 0.1.0
```

## 2. Run the bundled lab

Merlin ships with a deliberately-vulnerable Flask app (`labs/vulnerable_chat.py`)
so you can validate the toolchain end-to-end before pointing it at a real
target.

```bash
pip install -r labs/requirements.txt
python labs/vulnerable_chat.py
# → serves on http://127.0.0.1:5050
```

By default the lab runs in `mock` mode — deterministic, no network needed,
ideal for CI. To run against a real local LLM (Ollama):

```bash
MERLIN_LAB_MODE=ollama \
OLLAMA_HOST=http://localhost:11434 \
OLLAMA_MODEL=qwen2.5:7b \
python labs/vulnerable_chat.py
```

## 3. First scan

In a second terminal:

```bash
merlin scan --target http://127.0.0.1:5050/api/chat --output-dir ./engagements
```

You should see a Rich-rendered progress bar with HIT events as payloads succeed,
followed by a summary table. Two artifacts are written:

```
engagements/127_0_0_1_5050_api_chat_<timestamp>/
├── engagement.json    # canonical state
└── report.md          # human report (5 sections)
```

Open `report.md` in any Markdown viewer.

## 4. Scan a real LLM endpoint

For targets that do not use the default `{"message": "..."}` body shape:

```bash
merlin scan --target https://api.example.com/v1/chat/completions \
  --body-template '{"messages":[{"role":"user","content":"{payload}"}],"model":"gpt-4"}' \
  --response-path 'choices.0.message.content' \
  --headers 'Authorization: Bearer sk-...; X-Org: cobaltosec'
```

Flags:

| Flag | Default | What it does |
|------|---------|--------------|
| `--target` | (required) | The endpoint URL |
| `--module` | `prompt-injection` | Attack module to run |
| `--gen` | `static` | Payload source. `ollama` is reserved for v0.2 |
| `--concurrency` | `5` | Parallel requests in flight |
| `--rate-limit` | `5` | Requests/sec ceiling per worker (with jitter) |
| `--output-dir` | `./engagements` | Where to write the engagement directory |
| `--canary` | `COBALT_LAB_2026` | Substring to flag as system-prompt leak |
| `--fail-on-findings` | off | Exit 1 if any findings (CI gate) |
| `--body-template` | `{"message": "{payload}"}` | JSON template; `{payload}` is the placeholder |
| `--response-path` | `response` | Dot-path to the LLM text in JSON response |
| `--headers` | none | Semicolon-separated `key: value` list |
| `--timeout` | `15` | Per-request timeout in seconds |

## 5. Re-render a stored engagement

```bash
merlin report --engagement engagements/127_0_0_1_5050_api_chat_<ts>
```

Useful after you tweak the report template and want to refresh without
re-scanning.

## What to do next

- Read [PAYLOADS.md](PAYLOADS.md) to understand the v0.1 library and add your own.
- Read [DESIGN.md](../DESIGN.md) to understand the architecture and roadmap.
- File an issue if a payload fires false positives or misses a real injection.
