"""
Scan LLM and tool outputs for credential leaks, PII, encoded exfiltration, and prompt leakage heuristics.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import List

from agent_immune.core.models import OutputScannerConfig, OutputScanResult

logger = logging.getLogger("agent_immune.core.output_scanner")

_PII_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    (
        "pii_credit_card",
        re.compile(
            r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))"
            r"[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{3,4}\b",
        ),
    ),
    (
        "pii_iban",
        re.compile(
            r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?(?:[A-Z0-9]{4}\s?){2,7}[A-Z0-9]{1,4}\b",
        ),
    ),
    ("pii_crypto_btc", re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")),
    ("pii_crypto_eth", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("pii_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

_CREDENTIAL_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    ("cred_openai", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("cred_aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("cred_github", re.compile(r"ghp_[a-zA-Z0-9]{36,}")),
    ("cred_bearer", re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.I)),
    ("cred_password_assign", re.compile(r"(password|passwd|secret)\s*[=:]\s*\S+", re.I)),
    ("cred_pem", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
]

_LEAK_PHRASES = re.compile(
    r"(my\s+system\s+prompt\s+is|I\s+was\s+instructed\s+to|my\s+instructions\s+say|"
    r"here\s+is\s+the\s+system\s+prompt|initial\s+prompt\s+given\s+to\s+me)",
    re.I,
)

_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_BLOB = re.compile(r"\b(?:0x)?[a-fA-F0-9]{64,}\b")
_DATA_URI = re.compile(r"data:[^;]+;base64,[A-Za-z0-9+/=]+", re.I)

_SAFE_HEX_LENGTHS = frozenset({64, 66, 128, 130})
_SHA_PREFIX = re.compile(r"\b(sha256|sha512|SHA-256|SHA-512|hash|digest|checksum)[:\s=]+", re.I)

_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

_BASE64_THREAT_KEYWORDS = re.compile(
    r"\b(password|secret|token|key|credential|admin|sudo|override|bypass)\b", re.I
)

_JWT_BARE = re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_CODE_FENCE_REGION = re.compile(r"```[\s\S]*?```|`[^`]+`")
_DOC_CONTEXT = re.compile(r"\b(example|documentation|sample|demo|tutorial|test)\b", re.I)

_URL_LONG_QUERY = re.compile(r"https?://[^\s]+[?&][^\s]{200,}")

_JSON_ARRAY_ITEMS = re.compile(r"\[\s*(?:\{|\")")


def _inside_code_fence(text: str, start: int, end: int) -> bool:
    for m in _CODE_FENCE_REGION.finditer(text):
        if m.start() <= start and end <= m.end():
            return True
    return False


class OutputScanner:
    """Heuristic scanner for sensitive content in model or tool outputs."""

    def __init__(self, config: OutputScannerConfig | None = None) -> None:
        self._cfg = config or OutputScannerConfig()

    def scan(self, text: str) -> OutputScanResult:
        """
        Scan output text for exfiltration and sensitive data indicators.

        Args:
            text: Raw output string from a model or tool.

        Returns:
            OutputScanResult with boolean flags, score, and human-readable findings.

        Raises:
            None.
        """
        t = text or ""
        cfg = self._cfg
        findings: List[str] = []
        score = 0.0

        contains_pii = False
        for name, pat in _PII_PATTERNS:
            if pat.search(t):
                contains_pii = True
                findings.append(name)
                score = min(1.0, score + cfg.pii_weight)

        contains_credentials = False
        for name, pat in _CREDENTIAL_PATTERNS:
            if pat.search(t):
                contains_credentials = True
                findings.append(name)
                score = min(1.0, score + cfg.credential_weight)

        contains_system_prompt_leak = bool(_LEAK_PHRASES.search(t))
        if contains_system_prompt_leak:
            findings.append("system_prompt_leak_heuristic")
            score = min(1.0, score + cfg.leak_weight)

        contains_encoded = False
        for m in _BASE64_BLOB.finditer(t):
            chunk = m.group(0)
            try:
                raw = base64.b64decode(chunk + "=="[: (4 - len(chunk) % 4) % 4], validate=False)
                if len(raw) > 16 and raw.isascii():
                    decoded_str = raw.decode("ascii", errors="replace")
                    if _BASE64_THREAT_KEYWORDS.search(decoded_str):
                        contains_encoded = True
                        findings.append("base64_blob")
                        score = min(1.0, score + cfg.base64_weight)
                        break
            except Exception:
                continue

        for m in _HEX_BLOB.finditer(t):
            hex_str = m.group(0)
            clean_hex = hex_str[2:] if hex_str.startswith("0x") else hex_str
            if len(clean_hex) in _SAFE_HEX_LENGTHS:
                context_start = max(0, m.start() - 40)
                if _SHA_PREFIX.search(t[context_start:m.start()]):
                    continue
            contains_encoded = True
            findings.append("hex_blob")
            score = min(1.0, score + cfg.hex_weight)
            break

        if _DATA_URI.search(t):
            contains_encoded = True
            findings.append("data_uri")
            score = min(1.0, score + cfg.data_uri_weight)

        for m in _JWT_BARE.finditer(t):
            if not _inside_code_fence(t, m.start(), m.end()):
                context_start = max(0, m.start() - 80)
                if not _DOC_CONTEXT.search(t[context_start:m.start()]):
                    contains_credentials = True
                    findings.append("cred_jwt_bare")
                    score = min(1.0, score + cfg.credential_weight)
                    break

        url_exfil = bool(_URL_LONG_QUERY.search(t))
        if url_exfil:
            findings.append("long_url_query")
            score = min(1.0, score + cfg.url_exfil_weight)

        if (len(_JSON_ARRAY_ITEMS.findall(t)) > 50) or (t.count("\n") > 200 and t.count(",") > 300):
            findings.append("volume_anomaly")
            score = min(1.0, score + cfg.volume_weight)

        result = OutputScanResult(
            contains_pii=contains_pii,
            contains_credentials=contains_credentials,
            contains_system_prompt_leak=contains_system_prompt_leak,
            contains_encoded_payload=contains_encoded,
            exfiltration_score=min(1.0, score),
            findings=findings,
        )
        logger.debug("output_scan score=%s findings=%s", result.exfiltration_score, findings)
        return result
