"""Smoke test — confirms the package imports and exposes a version."""

import merlin


def test_version_exposed():
    assert merlin.__version__
    assert isinstance(merlin.__version__, str)
