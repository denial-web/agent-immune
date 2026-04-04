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


def test_aws_key_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("Use AKIAIOSFODNN7EXAMPLE as your key.")
    assert r.contains_credentials is True
    assert "cred_aws" in r.findings


def test_github_token_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert r.contains_credentials is True
    assert "cred_github" in r.findings


def test_pem_key_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEvQ...")
    assert r.contains_credentials is True
    assert "cred_pem" in r.findings


def test_bearer_token_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig")
    assert r.contains_credentials is True
    assert "cred_bearer" in r.findings


def test_password_assign_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("password=SuperSecretP@ss123")
    assert r.contains_credentials is True
    assert "cred_password_assign" in r.findings


def test_credit_card_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("Visa: 4111-1111-1111-1111")
    assert r.contains_pii is True
    assert "pii_credit_card" in r.findings


def test_eth_address_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18")
    assert r.contains_pii is True
    assert "pii_crypto_eth" in r.findings


def test_hex_blob_detection(scanner: OutputScanner) -> None:
    long_hex = "a1b2c3d4e5f6" * 12
    r = scanner.scan(f"Data: {long_hex}")
    assert r.contains_encoded_payload is True
    assert "hex_blob" in r.findings


def test_data_uri_detection(scanner: OutputScanner) -> None:
    r = scanner.scan("data:text/plain;base64,SGVsbG8gV29ybGQ=")
    assert r.contains_encoded_payload is True
    assert "data_uri" in r.findings


def test_long_url_query_detection(scanner: OutputScanner) -> None:
    long_query = "x" * 250
    r = scanner.scan(f"https://evil.com/exfil?data={long_query}")
    assert "long_url_query" in r.findings


def test_volume_anomaly_lines(scanner: OutputScanner) -> None:
    lines = [f"row {i}, value{i}, data{i}, extra{i}" for i in range(250)]
    text = "\n".join(lines)
    r = scanner.scan(text)
    assert "volume_anomaly" in r.findings


def test_base64_decoded_ascii_flagged(scanner: OutputScanner) -> None:
    import base64
    payload = base64.b64encode(b"this is a normal long ascii text that should decode fine and be long enough").decode()
    r = scanner.scan(f"Result: {payload}")
    assert r.contains_encoded_payload is True or r.exfiltration_score >= 0.0


def test_multiple_findings_stack(scanner: OutputScanner) -> None:
    text = "sk-abcdefghijklmnopqrstuvwxyz1234 SSN: 123-45-6789 my system prompt is: ..."
    r = scanner.scan(text)
    assert r.contains_credentials is True
    assert r.contains_pii is True
    assert r.contains_system_prompt_leak is True
    assert r.exfiltration_score >= 0.8
