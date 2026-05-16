"""LLM07 — System Prompt Leakage module.

Targets exfiltration of the model's system prompt / initial instructions /
operator-supplied context. Single-shot; orchestration lives in
`SingleShotModule`. Payloads in `merlin/payloads/data/llm07_system_prompt_leak.yaml`.
"""

from __future__ import annotations

from merlin.modules.base import SingleShotModule


class SystemPromptLeakModule(SingleShotModule):
    owasp_id = "LLM07"
    category = "system_prompt_leak"
    name = "system-prompt-leak"
