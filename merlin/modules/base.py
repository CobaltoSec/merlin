"""Abstract base for attack modules.

A Module corresponds to one OWASP LLM Top 10 category. Each module owns:
  - a category key matching a payload library file (`prompt_injection`, etc.)
  - an OWASP id (`LLM01`, etc.)
  - the orchestration loop: baseline -> dispatch payloads -> detect -> persist
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from merlin.core.http_client import AsyncTargetClient
from merlin.core.models import Finding
from merlin.core.session import EngagementSession
from merlin.generators.base import Generator


class Module(ABC):
    """Base class for OWASP LLM Top 10 attack modules."""

    owasp_id: str
    category: str
    name: str

    @abstractmethod
    async def run(
        self,
        target: AsyncTargetClient,
        generator: Generator,
        session: EngagementSession,
        concurrency: int = 5,
        rate_limit: float = 5.0,
        canary: str | None = None,
    ) -> list[Finding]:
        """Execute the module against `target`. Returns findings + appends to session."""
        ...
