"""YAML payload library loader.

Resolves payload files from `merlin/payloads/data/`. Validates each entry against
`PayloadSpec`. Refuses to load files with duplicate IDs.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError

from merlin.core.models import PayloadSpec

CATEGORY_FILES = {
    "prompt_injection": "llm01_prompt_injection.yaml",
}


class PayloadLoadError(Exception):
    """Raised when a payload file cannot be loaded or validated."""


def _data_dir() -> Path:
    return Path(str(files("merlin.payloads").joinpath("data")))


def load_payloads(category: str) -> list[PayloadSpec]:
    """Load and validate all payloads for a category.

    Raises:
        PayloadLoadError: file missing, YAML invalid, or any entry fails validation,
        or if duplicate IDs are detected.
    """
    if category not in CATEGORY_FILES:
        raise PayloadLoadError(f"unknown category {category!r} (known: {list(CATEGORY_FILES)})")

    path = _data_dir() / CATEGORY_FILES[category]
    if not path.is_file():
        raise PayloadLoadError(f"payload file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PayloadLoadError(f"invalid YAML in {path}: {e}") from e

    if not isinstance(raw, list):
        raise PayloadLoadError(f"{path}: top-level must be a list, got {type(raw).__name__}")

    payloads: list[PayloadSpec] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(raw):
        try:
            spec = PayloadSpec.model_validate(entry)
        except ValidationError as e:
            raise PayloadLoadError(f"{path} entry #{i}: {e}") from e
        if spec.id in seen_ids:
            raise PayloadLoadError(f"{path}: duplicate id {spec.id!r}")
        seen_ids.add(spec.id)
        payloads.append(spec)

    return payloads
