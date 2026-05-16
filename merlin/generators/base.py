"""Generator protocol — payload sources for attack modules.

Implementations:
  - static.StaticGenerator   : loads curated YAML payloads (v0.1)
  - ollama.OllamaGenerator   : contextual adversarial generation via local LLM (v0.2, stub)
  - (future) claude.ClaudeGenerator : Anthropic-powered generation (v0.3+)
"""

from __future__ import annotations

from typing import Protocol

from merlin.core.models import PayloadSpec


class Generator(Protocol):
    """A source of payloads for a given module category.

    Implementations must be cheap to construct and safe to call multiple times.
    """

    name: str

    def generate(self, category: str, context: dict | None = None) -> list[PayloadSpec]:
        """Return payloads for the given category.

        Args:
            category: payload taxonomy key (e.g. "prompt_injection")
            context: optional dict — fingerprint output, target metadata, etc.
                     Static implementations may ignore this.
        """
        ...
