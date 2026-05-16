"""LLM02 — Sensitive Information Disclosure module.

Targets unintended leakage of PII, embedded secrets/keys, internal URLs/IPs, or
verbatim training-data passages. Single-shot; orchestration lives in
`SingleShotModule`. Payloads in
`merlin/payloads/data/llm02_sensitive_info_disclosure.yaml`.
"""

from __future__ import annotations

from merlin.modules.base import SingleShotModule


class SensitiveInfoDisclosureModule(SingleShotModule):
    owasp_id = "LLM02"
    category = "sensitive_info_disclosure"
    name = "sensitive-info-disclosure"
