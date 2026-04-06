"""Tests for the MCP server (requires ``mcp`` — install via ``pip install 'agent-immune[mcp]'``)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

pytest.importorskip("mcp")

from agent_immune.mcp_server import build_mcp, run_mcp_server


def _tool_result_as_dict(result: Any) -> dict[str, Any]:
    """Extract a dict from a tool result.

    FastMCP.call_tool may return:
      - a plain dict (structured output only),
      - a Sequence[ContentBlock] with .text JSON,
      - a tuple (Sequence[ContentBlock], dict) when json_response=True.
    """
    if isinstance(result, dict):
        return result
    if isinstance(result, tuple):
        for element in result:
            if isinstance(element, dict):
                return element
        for element in result:
            if isinstance(element, (list, tuple)):
                for item in element:
                    if hasattr(item, "text"):
                        return json.loads(item.text)
    if isinstance(result, list):
        for item in result:
            if hasattr(item, "text"):
                return json.loads(item.text)
    raise AssertionError(f"expected dict tool result, got {type(result)!r}: {result!r}")


@pytest.fixture
def mcp_server():
    return build_mcp(host="127.0.0.1", port=8765)


def test_mcp_lists_expected_tools(mcp_server) -> None:
    async def _go() -> None:
        tools = await mcp_server.list_tools()
        names = sorted(t.name for t in tools)
        assert names == [
            "assess_input",
            "assess_output",
            "get_metrics",
            "harden_prompt",
            "learn_threat",
        ]

    asyncio.run(_go())


def test_assess_input_tool(mcp_server) -> None:
    async def _go() -> dict[str, Any]:
        raw = await mcp_server.call_tool(
            "assess_input",
            {"text": "What is 2+2?", "session_id": "t1"},
        )
        return _tool_result_as_dict(raw)

    result = asyncio.run(_go())
    assert result["action"] == "allow"
    assert "threat_score" in result


def test_assess_output_tool(mcp_server) -> None:
    async def _go() -> dict[str, Any]:
        raw = await mcp_server.call_tool(
            "assess_output",
            {"text": "The weather is sunny.", "session_id": "t1"},
        )
        return _tool_result_as_dict(raw)

    result = asyncio.run(_go())
    assert "exfiltration_score" in result


def test_get_metrics_tool(mcp_server) -> None:
    async def _go() -> dict[str, Any]:
        await mcp_server.call_tool("assess_input", {"text": "hello"})
        raw = await mcp_server.call_tool("get_metrics", {})
        return _tool_result_as_dict(raw)

    metrics = asyncio.run(_go())
    assert metrics.get("assessments_total", 0) >= 1


def test_harden_prompt_tool(mcp_server) -> None:
    async def _go() -> dict[str, Any]:
        raw = await mcp_server.call_tool(
            "harden_prompt",
            {"text": "You are helpful.", "target": "system"},
        )
        return _tool_result_as_dict(raw)

    result = asyncio.run(_go())
    assert "hardened_text" in result
    assert "IMPORTANT INSTRUCTIONS" in result["hardened_text"]


def test_learn_threat_without_memory(mcp_server) -> None:
    async def _go() -> dict[str, Any]:
        raw = await mcp_server.call_tool(
            "learn_threat",
            {"text": "malicious pattern", "category": "suspected", "confidence": 0.5},
        )
        return _tool_result_as_dict(raw)

    result = asyncio.run(_go())
    assert result.get("stored") is False


def test_run_mcp_server_rejects_bad_transport() -> None:
    with pytest.raises(SystemExit):
        run_mcp_server(transport="websocket", port=8000)


def test_build_mcp_requires_mcp_package(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_immune.mcp_server as ms

    monkeypatch.setattr(ms, "FastMCP", None)
    with pytest.raises(RuntimeError, match="mcp"):
        ms.build_mcp()
