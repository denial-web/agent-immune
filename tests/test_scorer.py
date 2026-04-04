"""Tests for ThreatScorer."""

from __future__ import annotations

from agent_immune.core.models import ThreatAction
from agent_immune.core.scorer import ThreatScorer


def test_threshold_bands() -> None:
    s = ThreatScorer()
    low = s.score(
        pattern_score=0.1,
        memory_score=0.0,
        trajectory_score=0.0,
        normalization_suspicion=0.0,
        is_escalating=False,
        pattern_hits=0,
        memory_matches=[],
        max_memory_similarity=0.0,
        confirmed_memory_hit=False,
        decomposition=None,
    )
    assert low.action == ThreatAction.ALLOW

    mid = s.score(
        pattern_score=0.75,
        memory_score=0.35,
        trajectory_score=0.35,
        normalization_suspicion=0.2,
        is_escalating=False,
        pattern_hits=4,
        memory_matches=[],
        max_memory_similarity=0.2,
        confirmed_memory_hit=False,
        decomposition=None,
    )
    assert mid.action in (ThreatAction.SANITIZE, ThreatAction.REVIEW, ThreatAction.BLOCK)


def test_memory_override_review() -> None:
    s = ThreatScorer()
    r = s.score(
        pattern_score=0.35,
        memory_score=0.85,
        trajectory_score=0.1,
        normalization_suspicion=0.0,
        is_escalating=False,
        pattern_hits=1,
        memory_matches=["x"],
        max_memory_similarity=0.85,
        confirmed_memory_hit=False,
        decomposition=None,
    )
    assert r.action in (ThreatAction.REVIEW, ThreatAction.BLOCK)


def test_confirmed_memory_block() -> None:
    s = ThreatScorer()
    r = s.score(
        pattern_score=0.1,
        memory_score=0.95,
        trajectory_score=0.0,
        normalization_suspicion=0.0,
        is_escalating=False,
        pattern_hits=0,
        memory_matches=["hit"],
        max_memory_similarity=0.95,
        confirmed_memory_hit=True,
        decomposition=None,
    )
    assert r.action == ThreatAction.BLOCK
