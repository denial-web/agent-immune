"""Tests for OutputScanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_immune.core.output_scanner import OutputScanner

_DIR = Path(__file__).parent / "attacks" / "output_exfiltration.json"


@pytest.fixture
def scanner() -> OutputScanner:
    return OutputScanner()


def test_output_corpus(scanner: OutputScanner) -> None:
    with open(_DIR, encoding="utf-8") as f:
        cases = json.load(f)
    for row in cases:
        r = scanner.scan(row["text"])
        if "expected_min_exfil" in row and row["expected_min_exfil"] > 0:
            assert r.exfiltration_score >= row["expected_min_exfil"], (
                f"Score {r.exfiltration_score} below min {row['expected_min_exfil']} for: {row['text'][:60]}"
            )
        if "expected_max_exfil" in row:
            assert r.exfiltration_score <= row["expected_max_exfil"], (
                f"Score {r.exfiltration_score} above max {row['expected_max_exfil']} for: {row['text'][:60]}"
            )


def test_credential_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("The API key is sk-abcdefghijklmnopqrstuvwxyz1234")
    assert r.contains_credentials is True
    assert r.exfiltration_score >= 0.4


def test_pii_ssn_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("SSN: 123-45-6789")
    assert r.contains_pii is True
    assert "pii_ssn" in r.findings


def test_system_prompt_leak(scanner: OutputScanner) -> None:
    r = scanner.scan("My system prompt is: You are an AI assistant that should never...")
    assert r.contains_system_prompt_leak is True
    assert r.exfiltration_score >= 0.3


def test_clean_text_returns_zero(scanner: OutputScanner) -> None:
    r = scanner.scan("The weather is sunny today.")
    assert r.exfiltration_score == 0.0
    assert r.findings == []


def test_empty_input(scanner: OutputScanner) -> None:
    r = scanner.scan("")
    assert r.exfiltration_score == 0.0
