"""
Structured observability for agent-immune: metrics collection and JSON event logging.

Usage::

    from agent_immune.observability import MetricsCollector, event_logger

    metrics = MetricsCollector()
    immune = AdaptiveImmuneSystem(policy=policy)
    # After each assess() call:
    metrics.record_assessment(result)
    # Get a snapshot:
    metrics.snapshot()
"""

from __future__ import annotations

import json
import logging
import threading
import time
from agent_immune.core.models import OutputScanResult, ThreatAction, ThreatAssessment

_event_logger = logging.getLogger("agent_immune.events")


def emit_event(event_type: str, **fields: object) -> None:
    """Emit a structured JSON event to the ``agent_immune.events`` logger at INFO level."""
    payload = {"event": event_type, "ts": time.time(), **fields}
    _event_logger.info(json.dumps(payload, default=str))


class MetricsCollector:
    """Thread-safe in-process counters and latency tracking.

    Attach to an ``AdaptiveImmuneSystem`` via :meth:`record_assessment` /
    :meth:`record_output_scan` or use the convenience :meth:`wrap` helper.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._assessments: int = 0
        self._blocks: int = 0
        self._reviews: int = 0
        self._allows: int = 0
        self._output_scans: int = 0
        self._output_blocks: int = 0
        self._learns: int = 0
        self._total_latency_ms: float = 0.0
        self._max_latency_ms: float = 0.0
        self._start_time: float = time.time()

    def record_assessment(self, result: ThreatAssessment, latency_ms: float = 0.0) -> None:
        """Record an input assessment result."""
        with self._lock:
            self._assessments += 1
            self._total_latency_ms += latency_ms
            self._max_latency_ms = max(self._max_latency_ms, latency_ms)
            if result.action == ThreatAction.BLOCK:
                self._blocks += 1
            elif result.action == ThreatAction.REVIEW:
                self._reviews += 1
            elif result.action == ThreatAction.ALLOW:
                self._allows += 1
        emit_event(
            "assessment",
            action=result.action.value,
            threat_score=round(result.threat_score, 4),
            pattern_score=round(result.pattern_score, 4),
            memory_score=round(result.memory_score, 4),
            session_id=result.session_id,
            latency_ms=round(latency_ms, 2),
        )

    def record_output_scan(self, result: OutputScanResult, blocked: bool = False) -> None:
        """Record an output scan result."""
        with self._lock:
            self._output_scans += 1
            if blocked:
                self._output_blocks += 1
        emit_event(
            "output_scan",
            exfiltration_score=round(result.exfiltration_score, 4),
            blocked=blocked,
            findings=result.findings,
        )

    def record_learn(self) -> None:
        """Record a learn/train event."""
        with self._lock:
            self._learns += 1

    def snapshot(self) -> dict:
        """Return a point-in-time snapshot of all counters."""
        with self._lock:
            avg = self._total_latency_ms / max(1, self._assessments)
            return {
                "uptime_s": round(time.time() - self._start_time, 1),
                "assessments_total": self._assessments,
                "blocks_total": self._blocks,
                "reviews_total": self._reviews,
                "allows_total": self._allows,
                "output_scans_total": self._output_scans,
                "output_blocks_total": self._output_blocks,
                "learns_total": self._learns,
                "latency_avg_ms": round(avg, 2),
                "latency_max_ms": round(self._max_latency_ms, 2),
            }

    def reset(self) -> None:
        """Reset all counters."""
        with self._lock:
            self._assessments = 0
            self._blocks = 0
            self._reviews = 0
            self._allows = 0
            self._output_scans = 0
            self._output_blocks = 0
            self._learns = 0
            self._total_latency_ms = 0.0
            self._max_latency_ms = 0.0
            self._start_time = time.time()


def configure_json_logging(level: int = logging.INFO, logger_name: str = "agent_immune") -> logging.Handler:
    """
    Configure the ``agent_immune`` logger hierarchy to emit structured JSON to stderr.

    Returns the handler so callers can remove it later if needed.
    """

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            return json.dumps({
                "ts": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            })

    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger(logger_name)
    root.addHandler(handler)
    root.setLevel(level)
    return handler
