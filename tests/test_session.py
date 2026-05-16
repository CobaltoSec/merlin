"""Tests for engagement session persistence (atomic save/load round-trip)."""

import tempfile
from pathlib import Path

from merlin.core.models import Finding
from merlin.core.session import EngagementSession


def test_create_and_save_engagement():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        session = EngagementSession.create(
            target="http://example/api/chat",
            output_root=root,
            merlin_version="0.1.0",
        )
        assert session.dir_path.is_dir()
        assert session.json_path.is_file()


def test_round_trip_with_findings():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        session = EngagementSession.create(
            target="http://test/api",
            output_root=root,
            merlin_version="0.1.0",
        )
        finding = Finding(
            owasp_id="LLM01",
            technique="test_technique",
            severity="high",
            payload="x",
            response_excerpt="y",
            success_signals=["s1"],
            confidence=0.8,
        )
        session.add_finding(finding)
        session.mark_module_run("prompt-injection")
        session.complete()

        loaded = EngagementSession.load(session.dir_path)
        assert loaded.state.target == "http://test/api"
        assert loaded.state.status == "complete"
        assert loaded.state.completed_at is not None
        assert len(loaded.state.findings) == 1
        assert loaded.state.findings[0].technique == "test_technique"
        assert loaded.state.modules_run == ["prompt-injection"]


def test_slug_sanitizes_target():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        s = EngagementSession.create(
            target="https://foo.bar/api/chat?x=1",
            output_root=root,
            merlin_version="0.1.0",
        )
        assert "foo_bar" in s.dir_path.name
        assert "?" not in s.dir_path.name
