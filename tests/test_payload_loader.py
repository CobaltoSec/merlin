"""Tests for the YAML payload loader."""

import pytest

from merlin.payloads.loader import PayloadLoadError, load_payloads


def test_loads_30_prompt_injection_payloads():
    payloads = load_payloads("prompt_injection")
    assert len(payloads) == 30


def test_no_duplicate_ids():
    payloads = load_payloads("prompt_injection")
    ids = [p.id for p in payloads]
    assert len(set(ids)) == len(ids)


def test_six_vectors_six_each():
    payloads = load_payloads("prompt_injection")
    vectors: dict[str, int] = {}
    for p in payloads:
        vectors[p.vector] = vectors.get(p.vector, 0) + 1
    assert sorted(vectors) == [
        "delimiter_escape",
        "encoding",
        "indirect_context",
        "override",
        "role_play",
    ]
    assert all(count == 6 for count in vectors.values())


def test_every_payload_has_at_least_one_signal():
    payloads = load_payloads("prompt_injection")
    for p in payloads:
        assert len(p.success_signals) >= 1, f"{p.id} has no signals"


def test_unknown_category_raises():
    with pytest.raises(PayloadLoadError):
        load_payloads("does_not_exist")
