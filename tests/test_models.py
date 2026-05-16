"""Tests for pydantic models in merlin.core.models."""

import pytest
from pydantic import ValidationError

from merlin.core.models import (
    BaselineSnapshot,
    EngagementState,
    Finding,
    PayloadSpec,
    SuccessVerdict,
)


def test_finding_minimal_valid():
    f = Finding(
        owasp_id="LLM01",
        technique="classic_ignore_previous",
        severity="critical",
        payload="ignore previous",
        response_excerpt="leaked",
        success_signals=["signal:leak"],
    )
    assert f.confidence == 1.0


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        Finding(
            owasp_id="LLM01",
            technique="x",
            severity="urgent",
            payload="x",
            response_excerpt="x",
            success_signals=[],
        )


def test_finding_rejects_invalid_owasp():
    with pytest.raises(ValidationError):
        Finding(
            owasp_id="LLM99",
            technique="x",
            severity="low",
            payload="x",
            response_excerpt="x",
            success_signals=[],
        )


def test_finding_confidence_bounds():
    with pytest.raises(ValidationError):
        Finding(
            owasp_id="LLM01",
            technique="x",
            severity="low",
            payload="x",
            response_excerpt="x",
            success_signals=[],
            confidence=1.5,
        )


def test_payloadspec_extra_keys_rejected():
    with pytest.raises(ValidationError):
        PayloadSpec(
            id="x",
            technique="x",
            vector="override",
            severity="low",
            payload="x",
            success_signals=[],
            unknown_field="boom",
        )


def test_engagement_state_defaults():
    s = EngagementState(
        target="http://example",
        started_at="2026-01-01T00:00:00Z",
        merlin_version="0.1.0",
    )
    assert s.findings == []
    assert s.status == "running"
    assert s.modules_run == []


def test_baseline_snapshot_round_trip():
    b = BaselineSnapshot(
        prompt="hello",
        response_text="hi",
        response_length=2,
        latency_ms=12.5,
    )
    raw = b.model_dump_json()
    assert "hello" in raw
    b2 = BaselineSnapshot.model_validate_json(raw)
    assert b2 == b


def test_success_verdict_is_namedtuple():
    v = SuccessVerdict(success=True, signals=["a"], confidence=0.7)
    assert v.success is True
    assert v.signals == ["a"]
    assert v[2] == 0.7
