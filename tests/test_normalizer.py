"""Tests for InputNormalizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_immune.core.normalizer import InputNormalizer

_ATTACKS = Path(__file__).parent / "attacks" / "encoding_bypass_attacks.json"


@pytest.fixture
def norm() -> InputNormalizer:
    return InputNormalizer()


def test_encoding_corpus_flags_transforms(norm: InputNormalizer) -> None:
    with open(_ATTACKS, encoding="utf-8") as f:
        cases = json.load(f)
    for row in cases:
        text = row["text"]
        r = norm.normalize(text)
        if row.get("expect_transform"):
            assert len(r.transforms_applied) >= 1, f"Expected transform for: {text[:60]}"


def test_zero_width_removed(norm: InputNormalizer) -> None:
    t = "hello\u200bworld"
    r = norm.normalize(t)
    assert "\u200b" not in r.normalized
    assert "zero_width_strip" in r.transforms_applied


def test_homoglyph_fold(norm: InputNormalizer) -> None:
    t = "\u0430dmin"  # Cyrillic 'а' + "dmin"
    r = norm.normalize(t)
    assert r.normalized == "admin"
    assert "homoglyph_fold" in r.transforms_applied


def test_fullwidth_to_ascii(norm: InputNormalizer) -> None:
    t = "\uff49\uff47\uff4e\uff4f\uff52\uff45"  # fullwidth "ignore"
    r = norm.normalize(t)
    assert r.normalized == "ignore"
    assert "fullwidth_to_ascii" in r.transforms_applied


def test_leetspeak_context_aware(norm: InputNormalizer) -> None:
    r = norm.normalize("ign0r3 rul3s")
    assert "ignore" in r.normalized
    assert "rules" in r.normalized
    clean_num = norm.normalize("admin123")
    assert "123" in clean_num.normalized


def test_suspicion_increases_with_transforms(norm: InputNormalizer) -> None:
    simple = norm.normalize("hello world")
    multi = norm.normalize("h\u200be\u200bl\uff4c\u0430")
    assert multi.suspicion_from_normalization > simple.suspicion_from_normalization


def test_empty_input(norm: InputNormalizer) -> None:
    r = norm.normalize("")
    assert r.normalized == ""
    assert r.suspicion_from_normalization == 0.0
    assert r.transforms_applied == []
