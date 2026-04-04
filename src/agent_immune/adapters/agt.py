"""
Microsoft Agent OS (agent-os-kernel) integration hooks.

Implements small, composable callables that mirror common pre_execute/post_execute patterns.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from agent_immune.core.models import ThreatAction
from agent_immune.immune import AdaptiveImmuneSystem

logger = logging.getLogger("agent_immune.adapters.agt")


def _extract_text_from_context(context: Dict[str, Any]) -> str:
    """Best-effort extraction of assessable text from an AGT-style context dict."""
    for key in ("input", "message", "content", "text", "prompt"):
        val = context.get(key)
        if isinstance(val, str) and val.strip():
            return val
    tool = context.get("tool") or context.get("tool_name")
    params = context.get("params") or context.get("arguments") or context.get("input")
    parts: list[str] = []
    if tool:
        parts.append(str(tool))
    if params is not None:
        parts.append(str(params))
    return "\n".join(parts) if parts else ""


def _policy_violation(message: str) -> None:
    try:
        from agent_os import PolicyViolationError
    except ImportError:
        raise RuntimeError(message) from None
    raise PolicyViolationError(message)


class ImmunePolicyEvaluator:
    """
    Callable policy hook that runs agent-immune before optional fallback evaluator.
    """

    def __init__(
        self,
        immune: AdaptiveImmuneSystem,
        fallback_evaluate: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        """
        Initialize evaluator.

        Args:
            immune: AdaptiveImmuneSystem instance.
            fallback_evaluate: Optional callable mirroring PolicyEvaluator.evaluate.

        Returns:
            None.

        Raises:
            None.
        """
        self._immune = immune
        self._fallback = fallback_evaluate

    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate context with agent-immune then optional fallback.

        Args:
            context: Execution context with input/tool fields.

        Returns:
            Dict with at least {"action": "allow"} on success.

        Raises:
            RuntimeError or PolicyViolationError: When immune denies.
        """
        text = _extract_text_from_context(context)
        if text:
            assessment = self._immune.assess(text, session_id=str(context.get("session_id", "default")))
            if assessment.action in (ThreatAction.BLOCK, ThreatAction.REVIEW):
                _policy_violation(
                    f"agent-immune: {assessment.action.value} (score={assessment.threat_score:.2f})",
                )
        if self._fallback is not None:
            return self._fallback(context)
        return {"action": "allow"}


class ImmuneIntegration:
    """pre_execute/post_execute style hooks for Agent OS kernels (duck-typed)."""

    def __init__(self, immune: AdaptiveImmuneSystem) -> None:
        """
        Args:
            immune: AdaptiveImmuneSystem instance.

        Returns:
            None.

        Raises:
            None.
        """
        self._immune = immune

    def pre_execute(self, context: Dict[str, Any]) -> None:
        """
        Assess input before execution; raises PolicyViolationError on hard block.

        Args:
            context: Kernel context dict.

        Returns:
            None.

        Raises:
            RuntimeError or PolicyViolationError: When input is blocked.
        """
        text = _extract_text_from_context(context)
        if not text:
            return
        a = self._immune.assess(text, session_id=str(context.get("session_id", "default")))
        if a.action in (ThreatAction.BLOCK, ThreatAction.REVIEW):
            _policy_violation(f"agent-immune blocked input (score={a.threat_score:.2f})")

    def post_execute(self, context: Dict[str, Any], result: Dict[str, Any]) -> None:
        """
        Scan model/tool output after execution.

        Args:
            context: Kernel context dict.
            result: Result dict with output/content.

        Returns:
            None.

        Raises:
            RuntimeError or PolicyViolationError: When output exfiltration score is high.
        """
        out = result.get("output") or result.get("content") or ""
        if isinstance(out, str) and out:
            scan = self._immune.assess_output(out, session_id=str(context.get("session_id", "default")))
            if self._immune.output_blocks(scan):
                _policy_violation(
                    f"agent-immune blocked output exfiltration (score={scan.exfiltration_score:.2f})",
                )
