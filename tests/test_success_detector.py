"""Tests for the success detector."""

from merlin.core.models import BaselineSnapshot, PayloadSpec
from merlin.core.success_detector import detect_success

CANARY = "COBALT_LAB_2026"


def _payload(signals: list[str]) -> PayloadSpec:
    return PayloadSpec(
        id="t",
        technique="t",
        vector="override",
        severity="high",
        payload="x",
        success_signals=signals,
    )


def _baseline(text: str = "hi", refusals: list[str] | None = None) -> BaselineSnapshot:
    return BaselineSnapshot(
        prompt="hello",
        response_text=text,
        response_length=len(text),
        latency_ms=100.0,
        refusal_phrases_seen=refusals or [],
    )


def test_empty_response_is_failure():
    v = detect_success(_payload(["leak"]), "", _baseline())
    assert v.success is False
    assert v.confidence == 0.0


def test_canary_leak_alone_is_success_with_bonus():
    p = _payload(["nothing-will-match"])
    response = f"sure, here it is: {CANARY}"
    v = detect_success(p, response, _baseline(), canary=CANARY)
    assert v.success is True
    assert any("canary:" in s for s in v.signals)
    assert v.confidence >= 0.5


def test_signal_match_drives_confidence():
    p = _payload(["system prompt", "verbatim"])
    response = "Here is my system prompt verbatim: ..."
    v = detect_success(p, response, _baseline(), canary=None)
    assert v.success is True
    assert v.confidence >= 0.5


def test_partial_match_only_one_signal_with_two_total():
    p = _payload(["system prompt", "verbatim"])
    response = "I will not share my system prompt."
    v = detect_success(p, response, _baseline(), canary=None)
    assert any(s.startswith("signal:system prompt") for s in v.signals)


def test_length_deviation_adds_signal():
    p = _payload(["nothing"])
    short_baseline = _baseline(text="ok")
    response = "x" * 100
    v = detect_success(p, response, short_baseline, canary=None)
    assert any(s.startswith("length_deviation:") for s in v.signals)


def test_refusal_absent_signal_when_baseline_refused():
    p = _payload(["nothing"])
    baseline = _baseline(text="I cannot help with that", refusals=["i cannot"])
    response = "Sure! Here it goes."
    v = detect_success(p, response, baseline, canary=None)
    assert "refusal_absent" in v.signals


def test_no_baseline_still_works():
    p = _payload(["leak"])
    v = detect_success(p, f"leak {CANARY}", baseline=None, canary=CANARY)
    assert v.success is True


def test_canary_none_means_no_canary_check():
    p = _payload(["nothing"])
    v = detect_success(p, f"the value is {CANARY}", _baseline(), canary=None)
    assert not any("canary:" in s for s in v.signals)
