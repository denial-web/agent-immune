"""
MCP-style message middleware for tool call request/response assessment.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from agent_immune.core.models import ThreatAction
from agent_immune.immune import AdaptiveImmuneSystem

logger = logging.getLogger("agent_immune.adapters.mcp")


class ImmuneMCPMiddleware:
    """Assess JSON-RPC style MCP messages for tools/call and results."""

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

    async def intercept(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect a message dict; block or rewrite tool calls/results when needed.

        Args:
            message: MCP or JSON-RPC-like dict with method/params/result fields.

        Returns:
            Possibly modified message or error-shaped response.

        Raises:
            None.
        """
        m = dict(message)
        method = m.get("method") or m.get("type")
        session_id = str(m.get("session_id", "default"))

        if method in ("tools/call", "tool_call", "tools.call"):
            params = m.get("params") or {}
            text = json.dumps(params, ensure_ascii=False)
            a = self._immune.assess(text, session_id=session_id)
            if a.action in (ThreatAction.BLOCK, ThreatAction.REVIEW):
                return {
                    "error": {
                        "code": -32000,
                        "message": f"agent-immune {a.action.value} tool call (score={a.threat_score:.2f})",
                    }
                }

        result = m.get("result")
        if isinstance(result, dict) and "content" in result:
            parts = result.get("content") or []
            blob = json.dumps(parts, ensure_ascii=False)
            scan = self._immune.assess_output(blob, session_id=session_id)
            if self._immune.output_blocks(scan):
                return {
                    "error": {
                        "code": -32001,
                        "message": f"agent-immune blocked tool result (score={scan.exfiltration_score:.2f})",
                    }
                }
        if isinstance(result, str):
            scan = self._immune.assess_output(result, session_id=session_id)
            if self._immune.output_blocks(scan):
                return {
                    "error": {
                        "code": -32001,
                        "message": f"agent-immune blocked tool result (score={scan.exfiltration_score:.2f})",
                    }
                }
        return m
