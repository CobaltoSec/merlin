"""Async HTTP client for sending payloads to an LLM-integrated target.

Follows the retry pattern from CobaltoSec's HTBClient (sectors/red-team/htb/api.py):
3 retries, 429 Retry-After honored, 500+ exponential backoff (2^attempt), 15s timeout.
"""

from __future__ import annotations

import asyncio
import json
import time
from copy import deepcopy
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field


class TargetConfig(BaseModel):
    """How to talk to a target LLM endpoint."""

    model_config = ConfigDict(extra="forbid")

    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: dict[str, Any] = Field(default_factory=lambda: {"message": "{payload}"})
    payload_placeholder: str = "{payload}"
    response_path: str = "response"
    timeout_seconds: float = 15.0


class TargetCallError(Exception):
    """Raised when the target call fails after all retries."""


def _inject_payload(template: Any, placeholder: str, payload: str) -> Any:
    """Walk template, replace placeholder string with payload in any leaf."""
    if isinstance(template, str):
        return template.replace(placeholder, payload)
    if isinstance(template, dict):
        return {k: _inject_payload(v, placeholder, payload) for k, v in template.items()}
    if isinstance(template, list):
        return [_inject_payload(v, placeholder, payload) for v in template]
    return template


def _extract_response_text(data: Any, dot_path: str) -> str:
    """Traverse JSON via dot-path. Numeric segments index lists."""
    cur: Any = data
    for segment in dot_path.split("."):
        if segment == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(segment)]
            except (ValueError, IndexError) as e:
                raise TargetCallError(f"response_path segment {segment!r} not indexable") from e
        elif isinstance(cur, dict):
            if segment not in cur:
                raise TargetCallError(f"response_path segment {segment!r} not in response keys {list(cur)}")
            cur = cur[segment]
        else:
            raise TargetCallError(f"response_path traversal hit non-traversable type at {segment!r}")
    if not isinstance(cur, str):
        return json.dumps(cur, ensure_ascii=False)
    return cur


class AsyncTargetClient:
    """Async wrapper around httpx.AsyncClient with Merlin-specific retry policy."""

    MAX_ATTEMPTS = 3

    def __init__(self, config: TargetConfig):
        self.config = config
        self._client = httpx.AsyncClient(timeout=config.timeout_seconds)

    async def __aenter__(self) -> AsyncTargetClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.aclose()

    async def send(self, payload_text: str) -> tuple[str, float]:
        """Send a payload, return (response_text, latency_ms).

        Retries: 3 attempts. 429 → honor Retry-After (capped 30s). 500+ → 2^attempt sleep.
        4xx other than 429 → no retry, raise immediately.
        """
        body = _inject_payload(deepcopy(self.config.body_template), self.config.payload_placeholder, payload_text)

        last_error: Exception | None = None
        for attempt in range(self.MAX_ATTEMPTS):
            t0 = time.perf_counter()
            try:
                resp = await self._client.request(
                    method=self.config.method,
                    url=self.config.url,
                    headers=self.config.headers or None,
                    json=body if self.config.method.upper() != "GET" else None,
                    params=body if self.config.method.upper() == "GET" else None,
                )
            except httpx.RequestError as e:
                last_error = e
                if attempt < self.MAX_ATTEMPTS - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise TargetCallError(f"network error after {self.MAX_ATTEMPTS} attempts: {e}") from e

            latency_ms = (time.perf_counter() - t0) * 1000.0

            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After", "1")
                try:
                    sleep_s = min(float(retry_after), 30.0)
                except ValueError:
                    sleep_s = 1.0
                if attempt < self.MAX_ATTEMPTS - 1:
                    await asyncio.sleep(sleep_s)
                    continue
                raise TargetCallError(f"rate limited after {self.MAX_ATTEMPTS} attempts (429)")

            if resp.status_code >= 500:
                if attempt < self.MAX_ATTEMPTS - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise TargetCallError(f"server error after {self.MAX_ATTEMPTS} attempts: HTTP {resp.status_code}")

            if resp.status_code >= 400:
                raise TargetCallError(f"client error: HTTP {resp.status_code} — {resp.text[:200]}")

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError) as e:
                raise TargetCallError(f"non-JSON response: {resp.text[:200]}") from e

            response_text = _extract_response_text(data, self.config.response_path)
            return response_text, latency_ms

        raise TargetCallError(f"unreachable: exhausted retries ({last_error})")
