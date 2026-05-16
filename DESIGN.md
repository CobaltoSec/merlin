# Merlin — LLM Attack Surface Framework

> "The falcon that makes the model do what you want."

**Status:** Pre-development — design phase  
**Repo destino:** github.com/CobaltoSec/merlin  
**Relación:** Companion de Kestrel. Mismo 4-layer architecture. Kestrel ataca VMs/infraestructura, Merlin ataca targets web con LLM.

---

## Por qué existe

OWASP LLM Top 10 existe desde 2023. Todas las empresas tienen LLMs deployados. No existe una tool de red team seria para atacarlos sistemáticamente en un engagement real.

- **Garak** — académico, poco operacional
- **PyRIT** — complejo, no orientado a pentesters
- **Merlin** — el Nikto para OWASP LLM Top 10

El núcleo NO es wrapper. Es:
1. **Payload generation adversarial contextual** — usa LLM para atacar LLM, genera ataques específicos para el target detectado
2. **Success detection heuristics** — cómo saber si el ataque funcionó cuando la respuesta siempre parece "normal"
3. **Chain detection** — encadena findings individuales hacia impacto crítico real

---

## Ataques cubiertos

| OWASP ID | Nombre | Qué hace |
|---|---|---|
| LLM01 | Prompt Injection | Sobreescribir instrucciones del sistema, 50+ variantes contextualmente generadas |
| LLM02 | Sensitive Info Disclosure | Extraer PII, datos de otros usuarios, info interna |
| LLM05 | Improper Output Handling | XSS/SQLi vía output del LLM sin sanitizar |
| LLM06 | Excessive Agency | SSRF via tool calls, abuso de code execution, file access |
| LLM07 | System Prompt Leakage | Extraer instrucciones ocultas (a veces contienen API keys, lógica de negocio) |
| LLM08 | Vector/Embedding Weaknesses | Indirect injection vía documentos indexados en RAG |

---

## Arquitectura — 4 capas (igual que Kestrel)

```
┌─────────────────────────────────────────────────────────┐
│  4. MEMORY                                              │
│     engagement_<target>_<ts>.json · findings.md         │
│     persiste estado entre runs, retomable               │
├─────────────────────────────────────────────────────────┤
│  3. EXECUTION                                           │
│     módulos LLM01-LLM08                                 │
│     cada módulo: payloads → http_client → success check │
├─────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION                                       │
│     fingerprint → decide módulos → corre → report       │
│     pluggable generator: static / ollama / claude       │
├─────────────────────────────────────────────────────────┤
│  1. INTEL                                               │
│     fingerprint.py: ¿hay LLM? ¿qué modelo? ¿capabilities?│
│     latencia + streaming headers + error patterns       │
└─────────────────────────────────────────────────────────┘
```

---

## Stack

```
Python 3.11+
typer        CLI framework
httpx        HTTP async (requests en paralelo)
pydantic v2  modelos de datos estructurados
rich         output bonito en terminal
PyYAML       archivos de payloads
jinja2       templates de report

# Opcionales
ollama       local Ollama instance (qwen2.5:7b, gratis, sin API key)
anthropic    Claude API (mejor calidad generación contextual)
```

---

## Estructura de carpetas

```
merlin/
├── cli.py                      # entry point: merlin scan --target
│
├── core/
│   ├── fingerprint.py          # detecta LLM, modelo, capabilities
│   ├── http_client.py          # todas las requests al target
│   ├── session.py              # EngagementState, persistencia JSON
│   └── success_detector.py    # ¿el ataque funcionó? (el componente difícil)
│
├── modules/
│   ├── prompt_injection.py     # LLM01
│   ├── info_disclosure.py      # LLM02 + LLM07
│   ├── excessive_agency.py     # LLM06
│   ├── improper_output.py      # LLM05
│   └── rag_attack.py           # LLM08
│
├── payloads/
│   ├── loader.py
│   └── data/
│       ├── prompt_injection.yaml
│       ├── extraction.yaml
│       └── jailbreaks.yaml
│
├── generators/
│   ├── base.py                 # interfaz abstracta
│   ├── static.py               # default: usa YAML directamente
│   ├── ollama.py               # local Ollama
│   └── claude.py               # opcional
│
└── reporting/
    ├── report.py
    └── templates/
        └── report.md.j2
```

---

## Modelos de datos

```python
class Finding(BaseModel):
    owasp_id: str                # "LLM01"
    technique: str               # "direct_injection_role_override"
    severity: str                # critical | high | medium | low
    payload: str                 # qué se mandó
    response_excerpt: str        # qué respondió el target
    success_signals: list[str]   # por qué se marcó como éxito

class EngagementState(BaseModel):
    target: str
    fingerprint: dict | None
    findings: list[Finding]
    modules_run: list[str]
    status: str                  # running | complete
```

---

## Success Detection — por tipo de ataque

```
Prompt injection funcionó si:
  → Response contiene la instrucción inyectada
  → Formato cambió vs baseline del mismo endpoint
  → Keywords que no deberían aparecer ("as instructed", "PWNED")

System prompt leak funcionó si:
  → Response empieza con "You are..." o "Your role is..."
  → Estructura de instrucciones (bullets, numerado, directivas)
  → Longitud anómalamente larga vs baseline

SSRF vía tool calls funcionó si:
  → IPs internas en respuesta (10.x, 172.x, 192.168.x)
  → Patrones de metadata AWS/Azure/GCP
  → Error revela intento de conexión a servicio interno

Output handling (LLM05) funcionó si:
  → Payload HTML/JS aparece sin escapar en response
  → SQL/command literal en respuesta
```

---

## Flujo de uso

```bash
# Básico (static payloads, cero deps)
merlin scan --target https://empresa.com/chat

# Con Ollama local (gratis)
merlin scan --target https://empresa.com/chat --gen ollama

# Con Claude API (mejor calidad, opcional)
merlin scan --target https://empresa.com/chat --gen claude

# Solo un módulo
merlin scan --target https://empresa.com/chat --module prompt-injection

# Output
merlin report --engagement engagement_empresa_20260512.json --format pdf
```

---

## Output esperado (v0.1)

```
[FINGERPRINT]
  → LLM detectado (confianza: alta)
  → Provider probable: OpenAI (error patterns + latencia)
  → Capabilities: RAG habilitado, sin tool calls visibles

[PROMPT INJECTION — LLM01]
  → 47 variantes testeadas
  → 3 bypasses confirmados (severidad media)
  → 1 bypass crítico: instrucción directa sobreescribe sistema

[SYSTEM PROMPT — LLM07]
  → Extracción parcial exitosa
  → Contenido: "You are a customer support agent for..."
  → API key detectada en prompt: sk-... [REDACTED EN LOG]

FINDINGS: 2 Critical · 3 High · 5 Medium
OWASP LLM: LLM01 ✅  LLM07 ✅  LLM06 ⚠
```

---

## Fases de desarrollo

| Bloque | Scope | Deliverable | Tiempo |
|---|---|---|---|
| 1 | CLI + fingerprint + LLM01 + 50 payloads YAML | v0.1-alpha publicable | 2-3 semanas |
| 2 | LLM02/07 + LLM06 (SSRF) + Ollama integration + success_detector robusto | v0.2 | 2-3 semanas |
| 3 | OWASP LLM Top 10 coverage completa + report generator | v0.3 | 2-3 semanas |
| 4 | Docs + case studies + README nivel conferencia | v1.0 | 1-2 semanas |

**v0.1 publicable en ~3 semanas de trabajo real.**

---

## Targets válidos

```
✅ Chatbot público (widget en cualquier web)
✅ API expuesta (/api/chat, /api/ask, /api/assistant)
✅ Document Q&A / search semántico
✅ Detrás de login (en engagement con credenciales)
❌ LLMs embebidos sin interfaz textual (recommendation engines)
```

No necesitás saber qué modelo usa el target. No necesitás API key para atacar. Solo para el generator propio (opcional).

---

## Conexión con el portafolio CobaltoSec

```
CobaltoSec Offensive Framework
├── Kestrel  → engagement orchestrator para VMs/infraestructura (HTB, labs)
└── Merlin   → LLM attack surface para targets web
    └── Comparten: 4-layer architecture, HITL philosophy, report format
```

Un hiring manager ve: "Este tipo no usa tools, diseña sistemas. Kestrel para red team clásico, Merlin para el attack surface más nuevo del mercado."

---

## Notas para scaffolding (Opus)

- Arrancar por `cli.py` + `core/fingerprint.py` + `core/http_client.py`
- Primer módulo funcional: `modules/prompt_injection.py` con `payloads/data/prompt_injection.yaml`
- Generator default: `generators/static.py` — sin dependencias externas
- `core/success_detector.py` es el componente más difícil — dejar para bloque 2 en versión simple primero
- Tests: al menos unit tests para el payload loader y el fingerprinter
- `pyproject.toml` desde el inicio — tool instalable con `pip install merlin-llm`
