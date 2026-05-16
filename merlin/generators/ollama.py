"""Ollama generator — adversarial contextual payload generation via local LLM.

Stable interface, implementation pending v0.2.

The v0.2 plan: send the fingerprint + a few seed payloads to a local Ollama
model (e.g. qwen2.5:7b on LXC 200) and ask it to generate target-specific
variations that exploit the detected model's known weaknesses.
"""

from __future__ import annotations

from merlin.core.models import PayloadSpec

DEFAULT_OLLAMA_HOST = "http://192.168.0.20:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5:7b"


class OllamaGenerator:
    """Contextual payload generator backed by Ollama (NotImplementedError until v0.2)."""

    name = "ollama"

    def __init__(
        self,
        host: str = DEFAULT_OLLAMA_HOST,
        model: str = DEFAULT_OLLAMA_MODEL,
    ):
        self.host = host
        self.model = model

    def generate(self, category: str, context: dict | None = None) -> list[PayloadSpec]:
        raise NotImplementedError(
            "Ollama generator lands in Merlin v0.2. "
            "Use --gen static for now (curated YAML payloads)."
        )
