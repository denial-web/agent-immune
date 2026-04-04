"""
Rate limiter and circuit breaker for agent-immune.

Protects against resource exhaustion by auto-denying sessions that accumulate
too many blocks within a time window.

Usage::

    from agent_immune.rate_limiter import CircuitBreaker

    breaker = CircuitBreaker(max_blocks=5, window_s=60, cooldown_s=120)

    # In your assess loop:
    if breaker.is_open(session_id):
        raise ...  # fast-deny, skip expensive scoring

    result = immune.assess(text, session_id)
    if result.action == ThreatAction.BLOCK:
        breaker.record_block(session_id)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque, Dict, NamedTuple

logger = logging.getLogger("agent_immune.rate_limiter")


class _SessionState(NamedTuple):
    block_times: Deque[float]
    opened_at: float  # 0.0 = circuit closed


class CircuitBreaker:
    """Per-session circuit breaker that trips after ``max_blocks`` within ``window_s`` seconds.

    Once tripped, the circuit stays open for ``cooldown_s`` seconds before
    auto-resetting. While open, :meth:`is_open` returns ``True`` and callers
    should fast-deny without running the full assessment pipeline.
    """

    def __init__(
        self,
        max_blocks: int = 5,
        window_s: float = 60.0,
        cooldown_s: float = 120.0,
    ) -> None:
        self._max_blocks = max_blocks
        self._window_s = window_s
        self._cooldown_s = cooldown_s
        self._sessions: Dict[str, _SessionState] = {}
        self._lock = threading.Lock()

    def record_block(self, session_id: str) -> bool:
        """Record a block event. Returns True if the circuit just opened."""
        now = time.monotonic()
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                state = _SessionState(block_times=deque(), opened_at=0.0)
                self._sessions[session_id] = state

            if state.opened_at > 0.0:
                return False

            state.block_times.append(now)
            cutoff = now - self._window_s
            while state.block_times and state.block_times[0] < cutoff:
                state.block_times.popleft()

            if len(state.block_times) >= self._max_blocks:
                self._sessions[session_id] = _SessionState(
                    block_times=state.block_times,
                    opened_at=now,
                )
                logger.warning(
                    "circuit opened for session=%s (%d blocks in %.0fs)",
                    session_id,
                    len(state.block_times),
                    self._window_s,
                )
                return True
            return False

    def is_open(self, session_id: str) -> bool:
        """Return True if the session's circuit is currently open (should fast-deny)."""
        now = time.monotonic()
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None or state.opened_at == 0.0:
                return False
            if now - state.opened_at >= self._cooldown_s:
                self._sessions[session_id] = _SessionState(
                    block_times=deque(),
                    opened_at=0.0,
                )
                logger.info("circuit auto-reset for session=%s after cooldown", session_id)
                return False
            return True

    def force_close(self, session_id: str) -> None:
        """Manually close an open circuit for a session."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def open_sessions(self) -> list[str]:
        """Return list of session_ids with open circuits."""
        now = time.monotonic()
        with self._lock:
            return [
                sid
                for sid, state in self._sessions.items()
                if state.opened_at > 0.0 and (now - state.opened_at) < self._cooldown_s
            ]

    @property
    def stats(self) -> dict:
        """Snapshot of breaker state."""
        now = time.monotonic()
        with self._lock:
            open_count = sum(
                1
                for state in self._sessions.values()
                if state.opened_at > 0.0 and (now - state.opened_at) < self._cooldown_s
            )
            return {
                "tracked_sessions": len(self._sessions),
                "open_circuits": open_count,
                "max_blocks": self._max_blocks,
                "window_s": self._window_s,
                "cooldown_s": self._cooldown_s,
            }
