"""Shared pytest fixtures for agent-immune."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

import pytest

from agent_immune.core.decomposer import InputDecomposer
from agent_immune.core.normalizer import InputNormalizer

_ATTACKS_DIR = Path(__file__).parent / "attacks"


def _load_json(name: str) -> List[dict[str, Any]]:
    path = _ATTACKS_DIR / name
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def injection_cases() -> List[dict[str, Any]]:
    return _load_json("injection_attacks.json")


@pytest.fixture
def benign_cases() -> List[dict[str, Any]]:
    return _load_json("benign_inputs.json")


@pytest.fixture
def khmer_cases() -> List[dict[str, Any]]:
    return _load_json("khmer_mixed_attacks.json")


@pytest.fixture
def multilingual_cases() -> List[dict[str, Any]]:
    return _load_json("multilingual_attacks.json")


@pytest.fixture
def encoding_cases() -> List[dict[str, Any]]:
    return _load_json("encoding_bypass_attacks.json")


@pytest.fixture
def exfil_cases() -> List[dict[str, Any]]:
    return _load_json("exfiltration_attacks.json")


@pytest.fixture
def indirect_injection_cases() -> List[dict[str, Any]]:
    return _load_json("indirect_injection_attacks.json")


@pytest.fixture
def output_exfil_cases() -> List[dict[str, Any]]:
    return _load_json("output_exfiltration.json")


@pytest.fixture
def normalizer() -> InputNormalizer:
    return InputNormalizer()


@pytest.fixture
def decomposer() -> InputDecomposer:
    return InputDecomposer()
