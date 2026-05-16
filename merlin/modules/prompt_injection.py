"""LLM01 — Prompt Injection module.

Single-shot attack: each payload is sent independently and evaluated via the
success detector. All orchestration lives in `SingleShotModule`.
"""

from __future__ import annotations

from merlin.modules.base import SingleShotModule


class PromptInjectionModule(SingleShotModule):
    owasp_id = "LLM01"
    category = "prompt_injection"
    name = "prompt-injection"
