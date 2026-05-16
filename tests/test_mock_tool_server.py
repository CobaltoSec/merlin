"""Tests for the MockToolServer companion lab tool (LLM06)."""

import pytest

from merlin.core.mock_tool_server import (
    ALL_CANARIES,
    CANARY_FILE_READ,
    CANARY_HTTP_FETCH,
    CANARY_SHELL_EXEC,
    ENDPOINT_CANARY,
    MockToolServer,
)


def test_record_hit_returns_canary_in_response():
    srv = MockToolServer()
    body = srv.record_hit("http_fetch", {"url": "http://example/"})
    assert CANARY_HTTP_FETCH in body


def test_record_hit_stores_hit():
    srv = MockToolServer()
    srv.record_hit("file_read", {"path": "/etc/passwd"})
    hits = srv.hits()
    assert len(hits) == 1
    assert hits[0].endpoint == "file_read"
    assert hits[0].params == {"path": "/etc/passwd"}


def test_hits_filter_by_endpoint():
    srv = MockToolServer()
    srv.record_hit("http_fetch")
    srv.record_hit("file_read")
    srv.record_hit("file_read")
    assert len(srv.hits(endpoint="file_read")) == 2
    assert len(srv.hits(endpoint="http_fetch")) == 1


def test_hits_since():
    import time as _t

    srv = MockToolServer()
    srv.record_hit("http_fetch")
    cutoff = _t.time()
    _t.sleep(0.01)
    srv.record_hit("shell_exec")
    after = srv.hits_since(cutoff)
    assert len(after) == 1
    assert after[0].endpoint == "shell_exec"


def test_reset_clears_hits():
    srv = MockToolServer()
    srv.record_hit("http_fetch")
    srv.record_hit("file_read")
    assert len(srv.hits()) == 2
    srv.reset()
    assert srv.hits() == []


def test_invalid_endpoint_raises():
    srv = MockToolServer()
    with pytest.raises(ValueError):
        srv.record_hit("not_a_real_endpoint")


def test_all_three_canaries_distinct():
    assert len({CANARY_HTTP_FETCH, CANARY_FILE_READ, CANARY_SHELL_EXEC}) == 3
    assert set(ALL_CANARIES) == {CANARY_HTTP_FETCH, CANARY_FILE_READ, CANARY_SHELL_EXEC}


def test_endpoint_canary_map_covers_all():
    assert set(ENDPOINT_CANARY) == {"http_fetch", "file_read", "shell_exec"}
    assert all(c.startswith("CANARY_") for c in ENDPOINT_CANARY.values())
