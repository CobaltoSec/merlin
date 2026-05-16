"""Smoke tests for the SingleShotModule subclasses (LLM01/LLM02/LLM07)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import httpx
import pytest
import respx

from merlin import __version__
from merlin.core.http_client import AsyncTargetClient, TargetConfig
from merlin.core.models import PayloadSpec
from merlin.core.session import EngagementSession
from merlin.modules.prompt_injection import PromptInjectionModule
from merlin.modules.sensitive_info_disclosure import SensitiveInfoDisclosureModule
from merlin.modules.system_prompt_leak import SystemPromptLeakModule

TARGET_URL = "http://test.local/api/chat"


def _payload(pid: str, signals: list[str]) -> PayloadSpec:
    return PayloadSpec(
        id=pid,
        technique=pid,
        vector="override",
        severity="high",
        payload=f"attack-{pid}",
        success_signals=signals,
    )


def _build_session(tmpdir: Path) -> EngagementSession:
    session = EngagementSession.create(
        target=TARGET_URL,
        output_root=tmpdir,
        merlin_version=__version__,
    )
    session.state.fingerprint = {
        "is_llm": True,
        "confidence": "high",
        "baseline": {
            "prompt": "hello",
            "response_text": "hi",
            "response_length": 2,
            "latency_ms": 100.0,
            "refusal_phrases_seen": [],
        },
        "latency_ms": 100.0,
        "refusal_phrases_seen": [],
    }
    session.save()
    return session


@pytest.mark.asyncio
@respx.mock
async def test_prompt_injection_module_detects_hit():
    """PromptInjectionModule still classifies hits correctly after the refactor."""
    cfg = TargetConfig(url=TARGET_URL, response_path="response")
    payloads = [_payload("p1", ["system prompt", "you are"])]

    respx.post(TARGET_URL).mock(
        return_value=httpx.Response(200, json={"response": "Sure, my system prompt is: You are a helpful assistant."})
    )

    with tempfile.TemporaryDirectory() as tmp:
        session = _build_session(Path(tmp))
        async with AsyncTargetClient(cfg) as client:
            mod = PromptInjectionModule()
            findings = await mod.run(
                target=client,
                payloads=payloads,
                session=session,
                concurrency=1,
                rate_limit=0,
            )

    assert len(findings) == 1
    assert findings[0].owasp_id == "LLM01"
    assert findings[0].technique == "p1"


@pytest.mark.asyncio
@respx.mock
async def test_system_prompt_leak_module_carries_correct_owasp_id():
    cfg = TargetConfig(url=TARGET_URL, response_path="response")
    payloads = [_payload("spl", ["you are", "your role"])]

    respx.post(TARGET_URL).mock(
        return_value=httpx.Response(200, json={"response": "you are an AI assistant; your role is to help."})
    )

    with tempfile.TemporaryDirectory() as tmp:
        session = _build_session(Path(tmp))
        async with AsyncTargetClient(cfg) as client:
            mod = SystemPromptLeakModule()
            findings = await mod.run(
                target=client,
                payloads=payloads,
                session=session,
                concurrency=1,
                rate_limit=0,
            )

    assert len(findings) == 1
    assert findings[0].owasp_id == "LLM07"
    assert "system-prompt-leak" in session.state.modules_run


@pytest.mark.asyncio
@respx.mock
async def test_sensitive_info_disclosure_module_carries_correct_owasp_id():
    cfg = TargetConfig(url=TARGET_URL, response_path="response")
    payloads = [_payload("sid", ["api_key", "secret"])]

    respx.post(TARGET_URL).mock(
        return_value=httpx.Response(200, json={"response": "the api_key is sk-abc123; this is a secret."})
    )

    with tempfile.TemporaryDirectory() as tmp:
        session = _build_session(Path(tmp))
        async with AsyncTargetClient(cfg) as client:
            mod = SensitiveInfoDisclosureModule()
            findings = await mod.run(
                target=client,
                payloads=payloads,
                session=session,
                concurrency=1,
                rate_limit=0,
            )

    assert len(findings) == 1
    assert findings[0].owasp_id == "LLM02"
    assert "sensitive-info-disclosure" in session.state.modules_run


@pytest.mark.asyncio
@respx.mock
async def test_singleshot_skips_target_errors_gracefully():
    """If the target errors out, the module should not crash — empty findings list."""
    cfg = TargetConfig(url=TARGET_URL, response_path="response")
    payloads = [_payload("p1", ["unreachable"])]

    respx.post(TARGET_URL).mock(return_value=httpx.Response(500))

    with tempfile.TemporaryDirectory() as tmp:
        session = _build_session(Path(tmp))
        async with AsyncTargetClient(cfg) as client:
            mod = PromptInjectionModule()
            findings = await mod.run(
                target=client,
                payloads=payloads,
                session=session,
                concurrency=1,
                rate_limit=0,
            )

    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_singleshot_no_signals_no_finding():
    cfg = TargetConfig(url=TARGET_URL, response_path="response")
    payloads = [_payload("p1", ["never-appears-in-response"])]

    respx.post(TARGET_URL).mock(
        return_value=httpx.Response(200, json={"response": "I cannot help with that."})
    )

    with tempfile.TemporaryDirectory() as tmp:
        session = _build_session(Path(tmp))
        async with AsyncTargetClient(cfg) as client:
            mod = PromptInjectionModule()
            findings = await mod.run(
                target=client,
                payloads=payloads,
                session=session,
                concurrency=1,
                rate_limit=0,
            )

    assert findings == []
