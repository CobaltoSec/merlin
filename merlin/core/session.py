"""Engagement session — load/save EngagementState atomically.

Layout:
  engagements/
    └── <slug>_<ts>/
        ├── engagement.json    # canonical state, written incrementally
        └── report.md          # rendered at end of scan
"""

from __future__ import annotations

import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from merlin.core.models import EngagementState, Finding

SLUG_PATTERN = re.compile(r"[^a-z0-9]+")


def _slugify(target: str) -> str:
    """Stable, filesystem-safe slug derived from target URL."""
    parts = target.lower().split("://", 1)[-1]
    return SLUG_PATTERN.sub("_", parts).strip("_")[:60] or "target"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ts_compact() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


class EngagementSession:
    """Wrapper around EngagementState with disk persistence."""

    def __init__(self, state: EngagementState, dir_path: Path):
        self.state = state
        self.dir_path = dir_path

    @classmethod
    def create(cls, target: str, output_root: Path, merlin_version: str) -> EngagementSession:
        slug = _slugify(target)
        ts = _ts_compact()
        dir_path = output_root / f"{slug}_{ts}"
        dir_path.mkdir(parents=True, exist_ok=True)
        state = EngagementState(
            target=target,
            started_at=_now_iso(),
            merlin_version=merlin_version,
        )
        session = cls(state=state, dir_path=dir_path)
        session.save()
        return session

    @classmethod
    def load(cls, dir_path: Path) -> EngagementSession:
        json_path = dir_path / "engagement.json"
        if not json_path.is_file():
            raise FileNotFoundError(f"no engagement.json at {dir_path}")
        state = EngagementState.model_validate_json(json_path.read_text(encoding="utf-8"))
        return cls(state=state, dir_path=dir_path)

    @property
    def json_path(self) -> Path:
        return self.dir_path / "engagement.json"

    @property
    def report_path(self) -> Path:
        return self.dir_path / "report.md"

    def add_finding(self, finding: Finding) -> None:
        self.state.findings.append(finding)
        self.save()

    def mark_module_run(self, module_name: str) -> None:
        if module_name not in self.state.modules_run:
            self.state.modules_run.append(module_name)
            self.save()

    def complete(self) -> None:
        self.state.status = "complete"
        self.state.completed_at = _now_iso()
        self.save()

    def fail(self) -> None:
        self.state.status = "failed"
        self.state.completed_at = _now_iso()
        self.save()

    def save(self) -> None:
        """Atomic write: temp file in same dir, then os.replace()."""
        data = self.state.model_dump_json(indent=2)
        fd, tmp = tempfile.mkstemp(prefix="engagement_", suffix=".json.tmp", dir=str(self.dir_path))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, self.json_path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
