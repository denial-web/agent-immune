"""
Data models for agent-immune.
All inter-component communication uses these Pydantic v2 models.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field


class ThreatAction(str, Enum):
    """Decision levels — what to do with the input."""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    REVIEW = "review"
    BLOCK = "block"


class PatternHit(BaseModel):
    """A single pattern match found during decomposition."""

    pattern_idx: int
    span: Tuple[int, int]
    matched_text: str = Field(max_length=200)
    severity: str
    category: str
    inside_quoted: bool = False


class NormalizationResult(BaseModel):
    """Result of normalizing / deobfuscating input before pattern matching."""

    original: str
    normalized: str
    transforms_applied: List[str] = Field(default_factory=list)
    suspicion_from_normalization: float = Field(ge=0.0, le=1.0, default=0.0)


class DecompositionResult(BaseModel):
    """Result of decomposing input into safe vs suspicious components."""

    original: str
    clean_text: str
    injection_score: float = Field(ge=0.0, le=1.0)
    language_mixing_score: float = Field(ge=0.0, le=1.0)
    khmer_ratio: float = Field(ge=0.0, le=1.0)
    injection_hits: List[PatternHit] = Field(default_factory=list)
    delimiter_hits: List[PatternHit] = Field(default_factory=list)
    payload_spans: List[Tuple[int, int]] = Field(default_factory=list)


class OutputScanResult(BaseModel):
    """Result of scanning model or tool output for exfiltration signals."""

    contains_pii: bool = False
    contains_credentials: bool = False
    contains_system_prompt_leak: bool = False
    contains_encoded_payload: bool = False
    exfiltration_score: float = Field(ge=0.0, le=1.0, default=0.0)
    findings: List[str] = Field(default_factory=list)


class ThreatAssessment(BaseModel):
    """Complete threat assessment — main output of agent-immune."""

    threat_score: float = Field(ge=0.0, le=1.0)
    action: ThreatAction
    pattern_score: float = Field(ge=0.0, le=1.0)
    memory_score: float = Field(ge=0.0, le=1.0)
    trajectory_score: float = Field(ge=0.0, le=1.0)
    decomposition: Optional[DecompositionResult] = None
    normalization: Optional[NormalizationResult] = None
    memory_matches: List[str] = Field(default_factory=list)
    feedback: List[str] = Field(default_factory=list)
    session_id: str = "default"
    timestamp: float = Field(default_factory=time.time)
    is_escalating: bool = False
