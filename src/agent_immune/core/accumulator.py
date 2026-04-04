"""
Per-session threat trajectory using an exponential moving average and escalation heuristics.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Deque, Dict

logger = logging.getLogger("agent_immune.core.accumulator")


class ThreatAccumulator:
    """Track rolling threat scores per session and detect escalation trends."""

    def __init__(self, decay: float = 0.90, max_turns: int = 20) -> None:
        """
        Initialize accumulator.

        Args:
            decay: EMA decay factor for smoothing turn scores.
            max_turns: Maximum number of recent turn scores to retain.

        Returns:
            None.

        Raises:
            None.
        """
        self._decay = decay
        self._max_turns = max_turns
        self._scores: Deque[float] = deque(maxlen=max_turns)
        self._ema = 0.0
        self._session_max = 0.0
        self._blocked_count = 0
        self._lock = threading.Lock()

    def update(self, turn_score: float) -> float:
        """
        Incorporate a new turn score into the EMA.

        Args:
            turn_score: Threat score for this turn in [0, 1].

        Returns:
            Current smoothed accumulated score after update.

        Raises:
            None.
        """
        with self._lock:
            self._ema = self._decay * self._ema + (1.0 - self._decay) * turn_score
            self._scores.append(turn_score)
            if turn_score > self._session_max:
                self._session_max = turn_score
            if turn_score >= 0.72:
                self._blocked_count += 1
            logger.debug("accumulator update turn=%s ema=%s", turn_score, self._ema)
            return self._ema

    def is_escalating(self) -> bool:
        """
        Return True if recent second-half average exceeds first half by >25% and second half > 0.2.

        Args:
            None.

        Returns:
            True when an escalation pattern is detected.

        Raises:
            None.
        """
        with self._lock:
            if len(self._scores) < 4:
                return False
            turns = list(self._scores)
            mid = len(turns) // 2
            first = sum(turns[:mid]) / max(1, mid)
            second = sum(turns[mid:]) / max(1, len(turns) - mid)
            if second <= 0.20:
                return False
            return second > first * 1.25

    def is_alert(self, threshold: float = 0.60) -> bool:
        """
        Return True if the current EMA exceeds threshold.

        Args:
            threshold: EMA threshold for alert state.

        Returns:
            True if EMA is at or above threshold.

        Raises:
            None.
        """
        with self._lock:
            return self._ema >= threshold

    def reset(self) -> None:
        """
        Clear history and reset EMA to zero.

        Args:
            None.

        Returns:
            None.

        Raises:
            None.
        """
        with self._lock:
            self._scores.clear()
            self._ema = 0.0
            self._session_max = 0.0
            self._blocked_count = 0

    @property
    def ema(self) -> float:
        """Current exponential moving average (thread-safe read)."""
        with self._lock:
            return self._ema

    @property
    def history_score(self) -> float:
        """Independent history signal: blend of session-max and block frequency."""
        with self._lock:
            n = len(self._scores) or 1
            freq = min(1.0, self._blocked_count / n)
            return min(1.0, self._session_max * 0.6 + freq * 0.4)


class SessionAccumulatorRegistry:
    """Registry of ThreatAccumulator instances keyed by session_id."""

    def __init__(self, decay: float = 0.90, max_turns: int = 20) -> None:
        self._decay = decay
        self._max_turns = max_turns
        self._by_session: Dict[str, ThreatAccumulator] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> ThreatAccumulator:
        with self._lock:
            acc = self._by_session.get(session_id)
            if acc is None:
                acc = ThreatAccumulator(decay=self._decay, max_turns=self._max_turns)
                self._by_session[session_id] = acc
            return acc

    def reset(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._by_session:
                self._by_session[session_id].reset()
