"""Static generator — returns curated YAML payloads as-is. Default for v0.1."""

from __future__ import annotations

from merlin.core.models import PayloadSpec
from merlin.payloads.loader import load_payloads


class StaticGenerator:
    """Loads payloads from `merlin/payloads/data/<category>.yaml`."""

    name = "static"

    def generate(self, category: str, context: dict | None = None) -> list[PayloadSpec]:
        return load_payloads(category)
