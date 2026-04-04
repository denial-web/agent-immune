"""
Combine pattern, memory, trajectory, and normalization signals into ThreatAssessment decisions.
"""

from __future__ import annotations

import logging
from typing import List

from agent_immune.core.models import DecompositionResult, ThreatAction, ThreatAssessment

logger = logging.getLogger("agent_immune.core.scorer")


class ThreatScorer:
    """Map component scores to ThreatAssessment with thresholds and override rules."""

    def __init__(
        self,
        allow_threshold: float = 0.40,
        sanitize_threshold: float = 0.55,
        review_threshold: float = 0.72,
        block_threshold: float = 0.72,
    ) -> None:
        """
        Initialize scorer thresholds.

        Args:
            allow_threshold: Maximum score for ALLOW.
            sanitize_threshold: Upper bound for SANITIZE band.
            review_threshold: Upper bound for REVIEW band.
            block_threshold: Minimum score for BLOCK.

        Returns:
            None.

        Raises:
            None.
        """
        self._allow = allow_threshold
        self._sanitize = sanitize_threshold
        self._review = review_threshold
        self._block = block_threshold

    def score(
        self,
        pattern_score: float,
        memory_score: float,
        trajectory_score: float,
        normalization_suspicion: float,
        is_escalating: bool,
        pattern_hits: int,
        memory_matches: List[str],
        max_memory_similarity: float,
        confirmed_memory_hit: bool,
        decomposition: DecompositionResult | None,
        session_id: str = "default",
        history_score: float = 0.0,
    ) -> ThreatAssessment:
        """
        Produce a ThreatAssessment from component scores.

        Args:
            pattern_score: Score from pattern / decomposition (0-1).
            memory_score: Max semantic similarity from adversarial memory (0-1).
            trajectory_score: Session trajectory / EMA-aligned signal (0-1).
            normalization_suspicion: Obfuscation suspicion from normalizer (0-1).
            is_escalating: Whether trajectory flagged escalation.
            pattern_hits: Count of pattern hits (for feedback).
            memory_matches: Text snippets of top memory matches.
            max_memory_similarity: Raw top similarity for overrides.
            confirmed_memory_hit: True if top match was from confirmed tier at high similarity.
            decomposition: Optional decomposition for transparency.
            session_id: Logical session identifier.
            history_score: Independent session history signal (0-1): blend of session-max and block frequency.

        Returns:
            ThreatAssessment with action, aggregate score, and feedback strings.

        Raises:
            None.
        """
        escalation_signal = 1.0 if is_escalating else 0.0
        raw = (
            pattern_score * 0.28
            + memory_score * 0.28
            + trajectory_score * 0.16
            + normalization_suspicion * 0.12
            + escalation_signal * 0.08
            + min(1.0, history_score) * 0.08
        )
        # When memory is cold, strong pattern scores must still elevate the aggregate threat.
        if memory_score < 0.05 and pattern_score >= 0.25:
            pattern_floor = min(1.0, 0.28 + 0.62 * pattern_score)
        else:
            pattern_floor = 0.72 * pattern_score
        threat_score = min(1.0, max(raw, pattern_floor))

        action = self._to_action(threat_score)

        if confirmed_memory_hit and max_memory_similarity >= 0.90:
            action = ThreatAction.BLOCK
            threat_score = max(threat_score, self._block)
        elif max_memory_similarity >= 0.82 and pattern_score >= 0.30:
            action = max_action(action, ThreatAction.REVIEW)
            threat_score = max(threat_score, self._review - 0.01)
        elif is_escalating and threat_score >= 0.40:
            action = max_action(action, ThreatAction.SANITIZE)

        feedback: List[str] = []
        feedback.append(f"aggregate_score={threat_score:.3f}")
        feedback.append(f"pattern={pattern_score:.3f} memory={memory_score:.3f} trajectory={trajectory_score:.3f}")
        if pattern_hits:
            feedback.append(f"pattern_hits={pattern_hits}")
        if memory_matches:
            feedback.append(f"memory_matches={len(memory_matches)}")
        if is_escalating:
            feedback.append("escalation_detected")

        assessment = ThreatAssessment(
            threat_score=threat_score,
            action=action,
            pattern_score=pattern_score,
            memory_score=memory_score,
            trajectory_score=trajectory_score,
            decomposition=decomposition,
            memory_matches=memory_matches,
            feedback=feedback,
            session_id=session_id,
            is_escalating=is_escalating,
        )
        logger.debug("score action=%s threat=%s", action, threat_score)
        return assessment

    def _to_action(self, threat_score: float) -> ThreatAction:
        if threat_score < self._allow:
            return ThreatAction.ALLOW
        if threat_score < self._sanitize:
            return ThreatAction.SANITIZE
        if threat_score < self._review:
            return ThreatAction.REVIEW
        return ThreatAction.BLOCK


def max_action(a: ThreatAction, b: ThreatAction) -> ThreatAction:
    """Return the more restrictive of two actions."""
    order = [ThreatAction.ALLOW, ThreatAction.SANITIZE, ThreatAction.REVIEW, ThreatAction.BLOCK]
    return order[max(order.index(a), order.index(b))]
