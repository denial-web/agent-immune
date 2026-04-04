"""
LangChain callback handler that assesses tool inputs and outputs.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from agent_immune.core.models import ThreatAction
from agent_immune.immune import AdaptiveImmuneSystem

logger = logging.getLogger("agent_immune.adapters.langchain")


class ImmuneCallbackHandler:
    """BaseCallbackHandler that runs agent-immune on tool and LLM I/O."""

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
        try:
            from langchain.callbacks.base import BaseCallbackHandler

            self._BaseCallbackHandler = BaseCallbackHandler
        except ImportError as exc:
            self._BaseCallbackHandler = None
            self._import_error = exc
        else:
            self._import_error = None

    def build(self) -> Any:
        """
        Construct a LangChain BaseCallbackHandler subclass.

        Args:
            None.

        Returns:
            Handler instance.

        Raises:
            ImportError: When langchain is not installed.
        """
        if self._BaseCallbackHandler is None:
            raise ImportError("langchain is required for ImmuneCallbackHandler") from self._import_error
        immune = self._immune
        Base = self._BaseCallbackHandler

        class _Handler(Base):
            def on_tool_start(
                self,
                serialized: Dict[str, Any],
                input_str: str,
                **kwargs: Any,
            ) -> None:
                text = input_str or serialized.get("name") or ""
                if text:
                    r = immune.assess(str(text), session_id=str(kwargs.get("session_id", "default")))
                    if r.action in (ThreatAction.BLOCK, ThreatAction.REVIEW):
                        raise ValueError(f"agent-immune {r.action.value} tool input: {r.threat_score:.2f}")

            def on_tool_end(self, output: str, **kwargs: Any) -> None:
                out = output if isinstance(output, str) else str(output)
                scan = immune.assess_output(out, session_id=str(kwargs.get("session_id", "default")))
                if immune.output_blocks(scan):
                    raise ValueError(f"agent-immune blocked tool output: {scan.exfiltration_score:.2f}")

            def on_llm_end(self, response: Any, **kwargs: Any) -> None:
                texts: List[str] = []
                try:
                    for gen_list in getattr(response, "generations", []) or []:
                        for gen in gen_list:
                            t = getattr(gen, "text", None)
                            if t:
                                texts.append(t)
                except Exception:
                    pass
                blob = "\n".join(texts)
                if blob:
                    scan = immune.assess_output(blob, session_id=str(kwargs.get("session_id", "default")))
                    if immune.output_blocks(scan):
                        raise ValueError(f"agent-immune blocked LLM output: {scan.exfiltration_score:.2f}")

        return _Handler()
