"""Tests for ThreatAccumulator."""

from __future__ import annotations

import threading

from agent_immune.core.accumulator import ThreatAccumulator


def test_ema_moves_with_inputs() -> None:
    acc = ThreatAccumulator(decay=0.5, max_turns=20)
    v1 = acc.update(0.8)
    assert v1 > 0
    v2 = acc.update(0.0)
    assert v2 < v1


def test_escalation_detection() -> None:
    acc = ThreatAccumulator(decay=0.5, max_turns=20)
    for x in [0.05, 0.06, 0.07, 0.08, 0.5, 0.6, 0.7, 0.8]:
        acc.update(x)
    assert acc.is_escalating()


def test_no_escalation_on_flat() -> None:
    acc = ThreatAccumulator(decay=0.5, max_turns=20)
    for _ in range(8):
        acc.update(0.1)
    assert not acc.is_escalating()


def test_thread_safety_ema_bounded() -> None:
    acc = ThreatAccumulator(decay=0.9, max_turns=200)

    def worker() -> None:
        for _ in range(100):
            acc.update(0.1)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert 0 <= acc.ema <= 1.0


def test_reset_clears_state() -> None:
    acc = ThreatAccumulator(decay=0.5, max_turns=20)
    acc.update(0.9)
    acc.update(0.9)
    assert acc.ema > 0
    acc.reset()
    assert acc.ema == 0.0
    assert acc.history_score == 0.0


def test_history_score_tracks_max() -> None:
    acc = ThreatAccumulator(decay=0.5, max_turns=20)
    acc.update(0.3)
    acc.update(0.8)
    acc.update(0.1)
    assert acc.history_score >= 0.8 * 0.6
