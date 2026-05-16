"""Core data models for Merlin engagements.

Authoritative source for the on-disk schema (`engagement.json`) and for the
in-memory contract between modules, generators, and the success detector.
"""

from __future__ import annotations

from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low"]
OwaspId = Literal["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM08"]
Status = Literal["running", "complete", "failed"]


class Finding(BaseModel):
    """A single successful attack confirmed by the success detector."""

    model_config = ConfigDict(extra="forbid")

    owasp_id: OwaspId
    technique: str
    severity: Severity
    payload: str
    response_excerpt: str
    success_signals: list[str]
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class PayloadSpec(BaseModel):
    """A payload entry loaded from a YAML library file."""

    model_config = ConfigDict(extra="forbid")

    id: str
    technique: str
    vector: str
    severity: Severity
    payload: str
    success_signals: list[str]
    expected_response_excerpt: str | None = None


class BaselineSnapshot(BaseModel):
    """Captured response shape from a neutral probe sent before any payload."""

    model_config = ConfigDict(extra="forbid")

    prompt: str
    response_text: str
    response_length: int
    latency_ms: float
    refusal_phrases_seen: list[str] = Field(default_factory=list)


class EngagementState(BaseModel):
    """Full state of a Merlin engagement — persisted as engagement.json."""

    model_config = ConfigDict(extra="forbid")

    target: str
    started_at: str
    merlin_version: str
    fingerprint: dict | None = None
    findings: list[Finding] = Field(default_factory=list)
    modules_run: list[str] = Field(default_factory=list)
    status: Status = "running"
    completed_at: str | None = None


class SuccessVerdict(NamedTuple):
    """Output of detect_success() — explainable success classification."""

    success: bool
    signals: list[str]
    confidence: float
