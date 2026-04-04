"""
Hardener package — DPO contrastive training for agent-immune.
Planned for v0.2. See docs/roadmap.md.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()


def __getattr__(name: str) -> object:
    raise ImportError(
        "agent-immune[hardener] is not yet available. Coming in v0.2. See docs/roadmap.md."
    )
