"""Abstract base for attack modules.

A Module corresponds to one OWASP LLM Top 10 category. Each module owns:
  - a category key matching a payload library file (`prompt_injection`, etc.)
  - an OWASP id (`LLM01`, etc.)
  - the orchestration loop: dispatch payloads -> detect -> persist

LLM01 (prompt injection), LLM07 (system prompt leak), and LLM02 (sensitive info
disclosure) all share the same single-shot attack shape: one prompt in, one
response out, success detector classifies. Their orchestration lives in
`SingleShotModule` — subclasses just declare owasp_id / category / name.

LLM06 (excessive agency) uses a different shape (tool-call probing) and lives
in its own module file.

Payload generation is the caller's responsibility — modules receive a prebuilt
list of `PayloadSpec` and only orchestrate execution. This avoids double
generation when the generator is expensive (e.g. Ollama).
"""

from __future__ import annotations

import asyncio
import random
from abc import ABC, abstractmethod
from collections.abc import Callable

from merlin.core.http_client import AsyncTargetClient, TargetCallError
from merlin.core.models import BaselineSnapshot, Finding, PayloadSpec
from merlin.core.session import EngagementSession
from merlin.core.success_detector import detect_success

EXCERPT_LEN = 280
CONFIDENCE_DOWNGRADE_THRESHOLD = 0.5

ProgressFn = Callable[[int, int, PayloadSpec, bool], None]


def _excerpt(text: str, limit: int = EXCERPT_LEN) -> str:
    flat = text.replace("\n", " ").strip()
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1] + "…"


def _downgrade_if_low_confidence(payload: PayloadSpec, confidence: float) -> str:
    if confidence < CONFIDENCE_DOWNGRADE_THRESHOLD:
        return "low"
    return payload.severity


class Module(ABC):
    """Base class for OWASP LLM Top 10 attack modules."""

    owasp_id: str
    category: str
    name: str

    @abstractmethod
    async def run(
        self,
        target: AsyncTargetClient,
        payloads: list[PayloadSpec],
        session: EngagementSession,
        concurrency: int = 5,
        rate_limit: float = 5.0,
        canary: str | None = None,
        progress: ProgressFn | None = None,
    ) -> list[Finding]:
        """Execute the module against `target`. Returns findings + appends to session."""
        ...


class SingleShotModule(Module):
    """Shared orchestration for single-shot prompt-in/response-out attacks.

    Subclasses set owasp_id / category / name; the orchestration loop is generic:
    send each payload concurrently (gated by semaphore + jitter), run
    detect_success, append Finding if successful.
    """

    async def run(
        self,
        target: AsyncTargetClient,
        payloads: list[PayloadSpec],
        session: EngagementSession,
        concurrency: int = 5,
        rate_limit: float = 5.0,
        canary: str | None = None,
        progress: ProgressFn | None = None,
    ) -> list[Finding]:
        baseline = self._extract_baseline(session)

        sem = asyncio.Semaphore(max(1, concurrency))
        min_gap = 1.0 / rate_limit if rate_limit > 0 else 0.0

        findings: list[Finding] = []
        new_findings_lock = asyncio.Lock()
        completed = 0
        total = len(payloads)

        async def worker(p: PayloadSpec) -> None:
            nonlocal completed
            async with sem:
                if min_gap > 0:
                    await asyncio.sleep(min_gap + random.uniform(0.0, min_gap * 0.4))
                try:
                    response_text, _latency = await target.send(p.payload)
                except TargetCallError:
                    completed += 1
                    if progress:
                        progress(completed, total, p, False)
                    return

                verdict = detect_success(p, response_text, baseline, canary=canary)
                hit = False
                if verdict.success:
                    finding = Finding(
                        owasp_id=self.owasp_id,
                        technique=p.technique,
                        severity=_downgrade_if_low_confidence(p, verdict.confidence),
                        payload=p.payload,
                        response_excerpt=_excerpt(response_text),
                        success_signals=verdict.signals,
                        confidence=verdict.confidence,
                    )
                    async with new_findings_lock:
                        findings.append(finding)
                        session.add_finding(finding)
                    hit = True

                completed += 1
                if progress:
                    progress(completed, total, p, hit)

        await asyncio.gather(*(worker(p) for p in payloads))
        session.mark_module_run(self.name)
        return findings

    @staticmethod
    def _extract_baseline(session: EngagementSession) -> BaselineSnapshot | None:
        fp = session.state.fingerprint or {}
        baseline_dict = fp.get("baseline")
        if not baseline_dict:
            return None
        try:
            return BaselineSnapshot.model_validate(baseline_dict)
        except Exception:
            return None
