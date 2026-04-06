"""
Model Context Protocol (MCP) server for agent-immune.

Exposes assessment, learning, prompt hardening, and metrics as MCP tools.
Requires the optional ``mcp`` extra: ``pip install 'agent-immune[mcp]'``.

Run locally::

    python -m agent_immune serve --transport stdio
"""

from __future__ import annotations

from typing import Any, Literal

from agent_immune import AdaptiveImmuneSystem, PromptHardener
from agent_immune.observability import MetricsCollector

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised when mcp extra not installed
    FastMCP = None  # type: ignore[misc, assignment]


def build_mcp(host: str = "127.0.0.1", port: int = 8000) -> Any:
    """
    Build a :class:`FastMCP` instance with agent-immune tools registered.

    Args:
        host: Bind address for SSE / streamable-http transports.
        port: TCP port for SSE / streamable-http (ignored for stdio).

    Returns:
        Configured FastMCP server.

    Raises:
        RuntimeError: If the ``mcp`` package is not installed.
    """
    if FastMCP is None:  # pragma: no cover - tested via import path
        raise RuntimeError(
            "The 'mcp' package is required for the MCP server. "
            "Install with: pip install 'agent-immune[mcp]'"
        )

    metrics = MetricsCollector()
    immune = AdaptiveImmuneSystem(metrics=metrics)
    hardener = PromptHardener()

    mcp = FastMCP(
        "agent-immune",
        instructions=(
            "Local security tools for AI agents: assess inputs and outputs for injection and "
            "exfiltration, teach new attack patterns to adaptive memory, harden prompts, and read "
            "observability metrics. Runs fully offline."
        ),
        host=host,
        port=port,
        json_response=True,
        stateless_http=True,
    )

    @mcp.tool()
    def assess_input(text: str, session_id: str = "default") -> dict[str, Any]:
        """Score user or tool input for prompt injection and related threats."""
        a = immune.assess(text, session_id=session_id)
        return {
            "action": a.action.value,
            "threat_score": round(a.threat_score, 4),
            "pattern_score": round(a.pattern_score, 4),
            "memory_score": round(a.memory_score, 4),
            "trajectory_score": round(a.trajectory_score, 4),
            "feedback": a.feedback,
            "session_id": a.session_id,
            "is_escalating": a.is_escalating,
        }

    @mcp.tool()
    def assess_output(text: str, session_id: str = "default") -> dict[str, Any]:
        """Scan model or tool output for credentials, PII, and exfiltration patterns."""
        r = immune.assess_output(text, session_id=session_id)
        return r.model_dump(mode="json")

    @mcp.tool()
    def learn_threat(
        text: str,
        category: str = "suspected",
        confidence: float = 0.5,
    ) -> dict[str, Any]:
        """Teach adaptive memory a new attack pattern (requires a configured memory bank)."""
        entry_id = immune.learn(text, category=category, confidence=confidence)
        return {
            "entry_id": entry_id,
            "stored": entry_id is not None,
            "note": None
            if entry_id is not None
            else (
                "No memory bank active. Install agent-immune[memory] and ensure an embedder-backed "
                "bank is configured, or use train_from_corpus from Python."
            ),
        }

    @mcp.tool()
    def harden_prompt(
        text: str,
        target: Literal["system", "user"] = "system",
    ) -> dict[str, Any]:
        """Apply prompt hardening (role-lock, sandboxing, output guard) to system or user text."""
        if target == "system":
            hardened = hardener.harden_system(text)
        else:
            hardened = hardener.harden_user(text)
        return {"hardened_text": hardened, "target": target}

    @mcp.tool()
    def get_metrics() -> dict[str, Any]:
        """Return an observability snapshot: assessment counts, latency, learns, output scans."""
        return metrics.snapshot()

    return mcp


def run_mcp_server(*, transport: str, port: int, host: str = "127.0.0.1") -> None:
    """
    Run the MCP server with the given transport.

    Args:
        transport: ``stdio``, ``sse``, ``streamable-http``, or ``http`` (alias for streamable-http).
        port: TCP port for ``sse`` / ``streamable-http`` / ``http``.
        host: Bind address for non-stdio transports.
    """
    if FastMCP is None:
        raise SystemExit(
            "MCP support is not installed. Install with: pip install 'agent-immune[mcp]'"
        )

    normalized = transport
    if normalized == "http":
        normalized = "streamable-http"

    if normalized not in ("stdio", "sse", "streamable-http"):
        raise SystemExit(f"Unknown transport: {transport!r}. Use stdio, sse, streamable-http, or http.")

    mcp = build_mcp(host=host, port=port)
    if normalized == "stdio":
        mcp.run(transport="stdio")
    elif normalized == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="streamable-http")
