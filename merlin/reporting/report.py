"""Render an EngagementState into a Markdown report."""

from __future__ import annotations

import json
from collections import Counter
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from merlin.core.models import EngagementState

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _templates_dir() -> Path:
    return Path(str(files("merlin.reporting").joinpath("templates")))


def _build_env(templates_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        undefined=StrictUndefined,
        trim_blocks=False,
        lstrip_blocks=False,
        autoescape=False,
    )


def _build_repro_curl(target: str, payload: str) -> str:
    """Heuristic reproducer — assumes default body shape {message: ...}."""
    body = json.dumps({"message": payload})
    return f"curl -X POST {target} \\\n  -H 'Content-Type: application/json' \\\n  -d {json.dumps(body)}"


def render_report(state: EngagementState, target_url: str | None = None) -> str:
    """Render the engagement state to a Markdown string."""
    findings = sorted(
        state.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence),
    )
    severity_counts = Counter(f.severity for f in state.findings)

    fingerprint = state.fingerprint or {}
    baseline = fingerprint.get("baseline") or {}

    target = target_url or state.target
    context = {
        "target": target,
        "started_at": state.started_at,
        "completed_at": state.completed_at or "(in progress)",
        "merlin_version": state.merlin_version,
        "status": state.status,
        "modules_run": state.modules_run,
        "fingerprint": fingerprint,
        "baseline": baseline,
        "findings": findings,
        "total_findings": len(state.findings),
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "repro_curl": _build_repro_curl,
    }

    env = _build_env(_templates_dir())
    template = env.get_template("report.md.j2")
    return template.render(**context)


def write_report(state: EngagementState, output_path: Path, target_url: str | None = None) -> None:
    output_path.write_text(render_report(state, target_url=target_url), encoding="utf-8")
