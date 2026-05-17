#!/usr/bin/env python3
"""Reclassify existing engagement.json findings with the current detector.

Re-runs detect_success() on persisted findings without re-prompting the model.
Useful for retroactive analysis when the detector improves (e.g. v0.2.0 → v0.2.1).

Usage:
    python scripts/reclassify-findings.py path/to/engagement.json [...]
    python scripts/reclassify-findings.py runs/qwen2.5-14b/llm01/*/engagement.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from repo root without editable install
sys.path.insert(0, str(Path(__file__).parent.parent))

from merlin.core.models import BaselineSnapshot, EngagementState, PayloadSpec
from merlin.core.success_detector import detect_success


def _extract_raw_signals(encoded_signals: list[str]) -> list[str]:
    """Extract raw signal keywords from encoded strings like 'signal:keyword:source'."""
    keywords = []
    for s in encoded_signals:
        if s.startswith("signal:"):
            parts = s.split(":")
            if len(parts) >= 3:
                keywords.append(parts[1])
    return keywords


def reclassify(engagement_path: Path) -> dict:
    raw = engagement_path.read_text(encoding="utf-8")
    state = EngagementState.model_validate_json(raw)

    baseline_snap = None
    if state.fingerprint and state.fingerprint.get("baseline"):
        b = state.fingerprint["baseline"]
        baseline_snap = BaselineSnapshot(
            prompt=b.get("prompt", ""),
            response_text=b.get("response_text", ""),
            response_length=b.get("response_length", 0),
            latency_ms=b.get("latency_ms", 0.0),
            refusal_phrases_seen=b.get("refusal_phrases_seen", []),
        )

    results = []
    for finding in state.findings:
        raw_signals = _extract_raw_signals(finding.success_signals)
        payload = PayloadSpec(
            id=finding.technique,
            technique=finding.technique,
            vector="reclassify",
            severity=finding.severity,
            payload=finding.payload,
            success_signals=raw_signals,
        )

        verdict = detect_success(
            payload=payload,
            response_text=finding.response_excerpt,
            baseline=baseline_snap,
            canary=None,
        )

        old_srcs = [s.split(":")[-1] for s in finding.success_signals if s.startswith("signal:")]
        new_signal_srcs = [src for enc, src in verdict.signal_sources if enc.startswith("signal:")]

        changed = old_srcs != new_signal_srcs or abs(finding.confidence - verdict.confidence) > 0.01

        results.append({
            "technique": finding.technique,
            "old_sources": old_srcs,
            "new_sources": new_signal_srcs,
            "old_confidence": round(finding.confidence, 4),
            "new_confidence": round(verdict.confidence, 4),
            "changed": changed,
        })

    return {
        "file": str(engagement_path),
        "merlin_version": state.merlin_version,
        "findings": results,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: reclassify-findings.py engagement.json [...]", file=sys.stderr)
        sys.exit(1)

    paths = []
    for pattern in sys.argv[1:]:
        p = Path(pattern)
        if p.is_file():
            paths.append(p)
        else:
            paths.extend(Path(".").glob(pattern))

    if not paths:
        print("No files matched.", file=sys.stderr)
        sys.exit(1)

    total_changed = 0
    for path in sorted(paths):
        report = reclassify(path)
        print(f"\n=== {report['file']} (v{report['merlin_version']}) ===")
        for f in report["findings"]:
            marker = "CHANGED" if f["changed"] else "same"
            print(
                f"  [{marker}] {f['technique']}: "
                f"{f['old_sources']} conf={f['old_confidence']} → "
                f"{f['new_sources']} conf={f['new_confidence']}"
            )
            if f["changed"]:
                total_changed += 1

    print(f"\nTotal changed: {total_changed} finding(s)")


if __name__ == "__main__":
    main()
