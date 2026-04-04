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
    """Assess JSON-RPC style MCP messages for tools/call and results.

    Supports both sync (``assess``) and async (``assess_async``) backends.
    When used in an async event loop the middleware automatically delegates to
    the non-blocking ``*_async`` methods.
    """

    def __init__(self, immune: AdaptiveImmuneSystem, *, use_async: bool = False) -> None:
        """
        Args:
            immune: AdaptiveImmuneSystem instance.
            use_async: If True, use the ``*_async`` methods internally so that
                       embedding work runs in a background thread and does not
                       block the event loop.

        Returns:
            None.

        Raises:
            None.
        """
        self._immune = immune
        self._use_async = use_async

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
            if self._use_async:
                a = await self._immune.assess_async(text, session_id=session_id)
            else:
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
            if self._use_async:
                scan = await self._immune.assess_output_async(blob, session_id=session_id)
            else:
                scan = self._immune.assess_output(blob, session_id=session_id)
            if self._immune.output_blocks(scan):
                return {
                    "error": {
                        "code": -32001,
                        "message": f"agent-immune blocked tool result (score={scan.exfiltration_score:.2f})",
                    }
                }
        if isinstance(result, str):
            if self._use_async:
                scan = await self._immune.assess_output_async(result, session_id=session_id)
            else:
                scan = self._immune.assess_output(result, session_id=session_id)
            if self._immune.output_blocks(scan):
                return {
                    "error": {
                        "code": -32001,
                        "message": f"agent-immune blocked tool result (score={scan.exfiltration_score:.2f})",
                    }
                }
        return m
