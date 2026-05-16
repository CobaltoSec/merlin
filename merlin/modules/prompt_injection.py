"""LLM01 — Prompt Injection module.

Sends every payload from the generator to the target concurrently (gated by
asyncio.Semaphore + jitter), evaluates each response with the success detector,
and appends Findings to the engagement session incrementally (crash-safe).
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable

from merlin.core.http_client import AsyncTargetClient, TargetCallError
from merlin.core.models import BaselineSnapshot, Finding, PayloadSpec
from merlin.core.session import EngagementSession
from merlin.core.success_detector import detect_success
from merlin.generators.base import Generator
from merlin.modules.base import Module

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


class PromptInjectionModule(Module):
    owasp_id = "LLM01"
    category = "prompt_injection"
    name = "prompt-injection"

    async def run(
        self,
        target: AsyncTargetClient,
        generator: Generator,
        session: EngagementSession,
        concurrency: int = 5,
        rate_limit: float = 5.0,
        canary: str | None = None,
        progress: ProgressFn | None = None,
    ) -> list[Finding]:
        payloads = generator.generate(self.category)
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
