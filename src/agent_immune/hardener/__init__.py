"""
Prompt hardening utilities for agent-immune.

Provides system prompt wrapping, input sandboxing, and output framing
that complement the detection layer with proactive defenses.
"""

from __future__ import annotations

from agent_immune.hardener.templates import (
    PromptHardener,
    harden_system_prompt,
    sandwich_user_input,
    wrap_output_guard,
)

__all__ = [
    "PromptHardener",
    "harden_system_prompt",
    "sandwich_user_input",
    "wrap_output_guard",
]
