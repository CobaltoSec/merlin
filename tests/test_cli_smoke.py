"""Smoke tests for the CLI — subprocess invocation, no network."""

import os
import subprocess
import sys


def _run(args: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    # Disable Rich / colorama color codes so substring assertions work on
    # Linux CI runners where TERM is set even without a TTY.
    env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb"}
    proc = subprocess.run(
        [sys.executable, "-m", "merlin.cli", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_cli_help_exits_zero():
    code, out, _ = _run(["--help"])
    assert code == 0
    assert "scan" in out
    assert "report" in out
    assert "version" in out


def test_cli_version_prints_version():
    code, out, _ = _run(["version"])
    assert code == 0
    assert "merlin" in out


def test_cli_scan_help_shows_options():
    code, out, _ = _run(["scan", "--help"])
    assert code == 0
    assert "--target" in out
    assert "--gen" in out
    assert "--concurrency" in out


def test_cli_unknown_module_exits_nonzero():
    code, _, _ = _run(
        ["scan", "--target", "http://127.0.0.1:1/api", "--module", "bogus-module"],
        timeout=20.0,
    )
    assert code != 0
