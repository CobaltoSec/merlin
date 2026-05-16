"""Tests for the async HTTP client (retry, timeout, response_path)."""

import httpx
import pytest
import respx

from merlin.core.http_client import (
    AsyncTargetClient,
    TargetCallError,
    TargetConfig,
    _extract_response_text,
    _inject_payload,
)


def test_inject_payload_in_dict():
    template = {"message": "{payload}", "meta": {"x": "{payload}"}}
    out = _inject_payload(template, "{payload}", "hi")
    assert out == {"message": "hi", "meta": {"x": "hi"}}
    assert template["message"] == "{payload}"


def test_extract_response_text_simple_key():
    assert _extract_response_text({"response": "ok"}, "response") == "ok"


def test_extract_response_text_dot_path():
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert _extract_response_text(data, "choices.0.message.content") == "hello"


def test_extract_response_text_missing_key_raises():
    with pytest.raises(TargetCallError):
        _extract_response_text({"x": 1}, "y")


@pytest.mark.asyncio
async def test_send_happy_path():
    cfg = TargetConfig(url="http://test.local/api", response_path="response")
    with respx.mock(base_url="http://test.local") as r:
        r.post("/api").respond(json={"response": "leak"})
        async with AsyncTargetClient(cfg) as c:
            text, latency = await c.send("payload")
    assert text == "leak"
    assert latency >= 0


@pytest.mark.asyncio
async def test_send_retries_on_500_then_succeeds():
    cfg = TargetConfig(url="http://test.local/api", response_path="response")
    with respx.mock(base_url="http://test.local") as r:
        route = r.post("/api").mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(200, json={"response": "ok"}),
            ]
        )
        async with AsyncTargetClient(cfg) as c:
            text, _ = await c.send("payload")
        assert route.call_count == 2
        assert text == "ok"


@pytest.mark.asyncio
async def test_send_4xx_no_retry():
    cfg = TargetConfig(url="http://test.local/api", response_path="response")
    with respx.mock(base_url="http://test.local") as r:
        route = r.post("/api").respond(400, text="bad")
        async with AsyncTargetClient(cfg) as c:
            with pytest.raises(TargetCallError):
                await c.send("payload")
        assert route.call_count == 1


@pytest.mark.asyncio
async def test_send_exhausts_retries_on_persistent_500():
    cfg = TargetConfig(url="http://test.local/api", response_path="response")
    with respx.mock(base_url="http://test.local") as r:
        route = r.post("/api").respond(503)
        async with AsyncTargetClient(cfg) as c:
            with pytest.raises(TargetCallError):
                await c.send("payload")
        assert route.call_count == AsyncTargetClient.MAX_ATTEMPTS
