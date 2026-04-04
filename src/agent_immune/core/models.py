"""
Data models for agent-immune.
All inter-component communication uses these Pydantic v2 models.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field


class ThreatAction(str, Enum):
    """Decision levels — what to do with the input."""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    REVIEW = "review"
    BLOCK = "block"


class SecurityPolicy(BaseModel):
    """
    Tunable knobs for threat detection sensitivity.

    Pass an instance to ``AdaptiveImmuneSystem(policy=...)`` to override defaults.
    Higher thresholds = more permissive; lower = more aggressive.
    """

    allow_threshold: float = Field(default=0.40, ge=0.0, le=1.0, description="Max score for ALLOW")
    sanitize_threshold: float = Field(default=0.55, ge=0.0, le=1.0, description="Max score for SANITIZE")
    review_threshold: float = Field(default=0.72, ge=0.0, le=1.0, description="Max score for REVIEW; above this = BLOCK")
    output_block_threshold: float = Field(default=0.72, ge=0.0, le=1.0, description="Output exfiltration score that triggers block")
    memory_confirm_threshold: float = Field(default=0.90, ge=0.0, le=1.0, description="Similarity to confirmed memory entry that forces BLOCK")
    memory_review_threshold: float = Field(default=0.82, ge=0.0, le=1.0, description="Similarity that upgrades to REVIEW when combined with patterns")
    escalation_upgrade: bool = Field(default=True, description="Whether escalation detection upgrades action severity")
    max_sessions: int = Field(default=10000, ge=1, description="LRU cap on session accumulator registry")

    model_config = ConfigDict(frozen=True)


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
    exfiltration_hits: List[PatternHit] = Field(default_factory=list)
    secret_hits: List[PatternHit] = Field(default_factory=list)
    escalation_hits: List[PatternHit] = Field(default_factory=list)
    delimiter_hits: List[PatternHit] = Field(default_factory=list)
    payload_spans: List[Tuple[int, int]] = Field(default_factory=list)

    @property
    def all_hits(self) -> List[PatternHit]:
        """All pattern hits across categories."""
        return self.injection_hits + self.exfiltration_hits + self.secret_hits + self.escalation_hits + self.delimiter_hits


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
