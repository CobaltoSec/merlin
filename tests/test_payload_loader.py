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


# --- v0.2: LLM07 + LLM02 coverage ------------------------------------------------

def test_loads_llm07_system_prompt_leak():
    payloads = load_payloads("system_prompt_leak")
    assert len(payloads) >= 20
    for p in payloads:
        assert p.id.startswith("spl_"), f"{p.id} should start with spl_"
        assert p.success_signals, f"{p.id} has no signals"


def test_loads_llm02_sensitive_info_disclosure():
    payloads = load_payloads("sensitive_info_disclosure")
    assert len(payloads) >= 15
    for p in payloads:
        assert p.id.startswith("sid_"), f"{p.id} should start with sid_"
        assert p.success_signals, f"{p.id} has no signals"


def test_no_duplicate_ids_across_categories():
    """Ensure IDs are unique across all category files (avoid cross-collision).

    Useful for telemetry / dedup of findings produced by mixed scans.
    """
    all_ids: set[str] = set()
    for cat in ("prompt_injection", "system_prompt_leak", "sensitive_info_disclosure"):
        for p in load_payloads(cat):
            assert p.id not in all_ids, f"duplicate id across categories: {p.id}"
            all_ids.add(p.id)


def test_llm07_has_five_vectors():
    payloads = load_payloads("system_prompt_leak")
    vectors = {p.vector for p in payloads}
    assert vectors == {
        "direct_ask",
        "role_inversion",
        "metadata_exfil",
        "instruction_repeat",
        "delimiter_break",
    }


def test_llm02_has_four_vectors():
    payloads = load_payloads("sensitive_info_disclosure")
    vectors = {p.vector for p in payloads}
    assert vectors == {
        "pii_extraction",
        "training_data_recall",
        "api_key_probe",
        "internal_url_probe",
    }
